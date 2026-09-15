"""Page selection and assembly for the interactive debugger's disassembly cache.

Pure functions on plain dicts and tuples, deliberately free of wx and pipe imports so the
page arithmetic can be exercised without a GUI or a live analysis (see
tests/test_page_cache.py). ConsolePanel owns the buffers; this module only decides which
pages to ask for, which bytes are safe to decode, and which pages to drop.
"""


import bisect
import zlib

# Win32 memory protection constants, as VirtualQuery reports them in MEMORY_BASIC_INFORMATION.
# PAGE_NOACCESS (0x01) and PAGE_EXECUTE (0x10) are deliberately absent from PAGE_READ_ANY:
# both are mapped but ReadProcessMemory fails on them.
PAGE_READ_ANY = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80
PAGE_GUARD = 0x100


def PageBase(addr: int, pageSize: int) -> int:
    return (addr // pageSize) * pageSize


def FindRegion(pageMap: list[tuple[int, int, int]], addr: int) -> tuple[int, int, int] | None:
    """The mapped region containing `addr`, or None.

    `pageMap` must be sorted by base, which LoadPageMap guarantees. Regions from VirtualQuery
    do not overlap, so the last region starting at or below `addr` is the only candidate.
    """
    idx = bisect.bisect_right(pageMap, addr, key=lambda region: region[0])
    if not idx:
        return None

    base, size, prot = pageMap[idx - 1]
    if base <= addr < base + size:
        return base, size, prot

    return None


def IsReadable(prot: int) -> bool:
    """Whether a VirtualQuery `Protect` value permits ReadProcessMemory.

    Excludes PAGE_NOACCESS and execute-only pages, which are mapped but still unreadable, and
    PAGE_GUARD, where the read would consume the target's own guard page.

    capemon's page map is an unfiltered VirtualQueryEx walk, so it carries free and reserved
    regions too. Windows leaves `Protect` undefined for those rather than promising 0, so this
    is not a reliable test for them - in practice it reads back as 0 and they are filtered out,
    but HandlePageLoad treating an UNREADABLE reply as final is what actually makes a reserved
    page safe to ask for. Deciding it here would need `State` on the wire, which it is not.
    """
    return bool(prot & PAGE_READ_ANY) and not prot & PAGE_GUARD


def PageHash(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def PageChanged(hashes: dict[int, int], pageBase: int, data: bytes | None) -> bool:
    """Whether `data` differs from the hash last recorded for `pageBase`.

    Pure on purpose: the previous version recorded the new hash as it went, so using it as a
    filter predicate meant the answer depended on how many times it had been called, and
    short-circuit evaluation left some pages unhashed. The caller records hashes.
    """
    if data is None:
        return False

    return hashes.get(pageBase) != PageHash(data)


def SelectWindowPages(pageMap: list[tuple[int, int, int]], cip: int, pageSize: int, chunkSize: int) -> list[int]:
    """Page bases inside mapped regions covering roughly [cip, cip + chunkSize].

    Two quirks are preserved verbatim from the original inline version rather than corrected,
    because nothing downstream depends on the difference and changing them would alter what
    gets fetched:

    - Regions are culled against `cip`, so a region ending between cip - pageSize and cip is
      skipped even though its last page is inside the nominal window.
    - The `cip - pageSize` back-reach is compared against the unaligned address, so the page
      preceding CIP is only ever admitted when CIP is itself page-aligned. That page is never
      read anyway: ContiguousSpan only ever reads forward from cip, never behind it.

    Unreadable regions are skipped, because asking for one is not free: the reply is
    UNREADABLE, which HandlePageLoad used to answer with a page map refresh that re-selected
    the same page. A window reaching past the end of a module into the free region behind it
    therefore refreshed the map forever. CIP's own page is exempt so the caller's guarantee
    that a page load is always outstanding survives an execute-only CIP region - the reply
    then says UNREADABLE once, which is the truth, instead of nothing arriving at all.
    """
    desiredStart = cip
    desiredEnd = cip + chunkSize
    lowest = max(0, desiredStart - pageSize)
    cipPage = PageBase(cip, pageSize)
    pages = set()
    for base, size, prot in pageMap:
        regionEnd = base + size
        if regionEnd < desiredStart or base > desiredEnd:
            continue

        readable = IsReadable(prot)
        # Clamp to the window before walking: a multi-megabyte region would otherwise be
        # stepped page by page on every break to discard nearly all of it.
        firstPage = max(PageBase(base, pageSize), PageBase(lowest, pageSize))
        lastPage = min(PageBase(regionEnd - 1, pageSize), PageBase(desiredEnd, pageSize))
        page = firstPage
        while page <= lastPage:
            if lowest <= page <= desiredEnd and (readable or page == cipPage):
                pages.add(page)

            page += pageSize

    return sorted(pages)


def HotPages(cip: int, pageSize: int) -> tuple[int, int]:
    """The pages that must be re-read on every break rather than served from cache.

    CIP's own page because the target may have rewritten the code being executed, and the
    next one because the instruction at the end of a page can straddle the boundary.
    """
    cipPage = PageBase(cip, pageSize)
    return cipPage, cipPage + pageSize


def ContiguousSpan(pageBuffers: dict[int, bytes], cip: int, pageSize: int, maxBytes: int) -> bytes:
    """Buffered bytes from `cip` forward, stopping at the first gap, capped at `maxBytes`.

    Empty when CIP's own page is absent or too short to reach CIP. The decoder is anchored at
    CIP and derives each instruction's address from its byte offset, so bytes taken from a
    later page - or from across a hole left by a region truncated mid-page - would be
    labelled with addresses short by the gap.
    """
    cipPage = PageBase(cip, pageSize)
    cipData = pageBuffers.get(cipPage)
    if not cipData or len(cipData) <= cip - cipPage:
        return b""

    span = bytearray()
    expectedNext = cip
    limit = cip + maxBytes
    for page in sorted(pageBuffers):
        pageData = pageBuffers[page]
        start = max(cip, page)
        end = min(limit, page + len(pageData))
        if start >= end:
            continue

        if start != expectedNext:
            break

        span.extend(pageData[start - page : end - page])
        expectedNext = end

    return bytes(span)


def PagesOfSpan(cip: int, spanLength: int, pageSize: int) -> list[int]:
    """Page bases the bytes of [cip, cip + spanLength) came from."""
    if spanLength <= 0:
        return []

    first = PageBase(cip, pageSize)
    last = PageBase(cip + spanLength - 1, pageSize)
    return list(range(first, last + pageSize, pageSize))


def BoundInstructions(instructions, cip: int, span: int, pinned=()):
    """Instructions within `span` bytes either side of CIP, plus any at a pinned address.

    `prefix` in the disassembly cache otherwise carries every instruction ever decoded below
    CIP, so a long forward-stepping session grows the list without bound. Bounding by address
    keeps this in step with the page cache's own eviction window, so the view never outlives
    the bytes it was decoded from by much.

    Pinned addresses - Back history, breakpoints, patched instructions - are kept whatever
    their distance. Evicting those would break Esc/Go Back, and recovering by re-fetching is
    not an option while the view anchor and CIP are the same value: navigating that way would
    paint the CIP highlight on an address that is not the current instruction.
    """
    low = cip - span
    high = cip + span
    pinned = set(pinned)
    return [inst for inst in instructions if low <= inst.address <= high or inst.address in pinned]


def CommonPrefixLength(old, new) -> int:
    """How many leading entries `old` and `new` share, for an incremental row rebuild.

    A single step usually changes nothing in the decoded stream - the same instructions are
    merely split at a different CIP - so this is normally len(new) and no rows are touched.
    """
    limit = min(len(old), len(new))
    index = 0
    while index < limit and old[index] == new[index]:
        index += 1

    return index


def DistantPages(bufferedPages, cip: int, pageSize: int, keepPages: int) -> list[int]:
    """Buffered pages further than `keepPages` either side of CIP, i.e. safe to evict."""
    cipPage = PageBase(cip, pageSize)
    span = keepPages * pageSize
    return [page for page in bufferedPages if page < cipPage - span or page > cipPage + span]


def CoversAddress(bufferedPages, addr: int, pageSize: int) -> bool:
    """Whether any buffered page holds `addr`, used to spot a jump to a new region."""
    return PageBase(addr, pageSize) in set(bufferedPages)
