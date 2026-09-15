"""Tests for the debugger's page selection and assembly arithmetic.

CAPEsolo.capelib.page_cache is deliberately free of wx and pipe imports so these run without
a GUI, a monitor, or a live analysis:

    ./.venv/Scripts/python.exe -m pytest tests/test_page_cache.py
"""

from CAPEsolo.capelib.page_cache import (
    BoundInstructions,
    CommonPrefixLength,
    ContiguousSpan,
    CoversAddress,
    DistantPages,
    FindRegion,
    HotPages,
    PageBase,
    PageChanged,
    PageHash,
    PagesOfSpan,
    SelectWindowPages,
)

PAGE_SIZE = 4 * 1024
CHUNK_SIZE = (65 * 1024) // 2
KEEP_PAGES = 16

# base, size, protect - the shape LoadPageMap produces.
ONE_REGION = [(0x10000, 0x10000, 0x20)]


def test_page_base_rounds_down():
    assert PageBase(0x10000, PAGE_SIZE) == 0x10000
    assert PageBase(0x10FFF, PAGE_SIZE) == 0x10000
    assert PageBase(0x11000, PAGE_SIZE) == 0x11000


def test_hot_pages_are_cip_page_and_successor():
    assert HotPages(0x10005, PAGE_SIZE) == (0x10000, 0x11000)
    assert HotPages(0x10000, PAGE_SIZE) == (0x10000, 0x11000)


def test_window_covers_cip_page_and_stays_inside_the_region():
    pages = SelectWindowPages(ONE_REGION, 0x10005, PAGE_SIZE, CHUNK_SIZE)
    assert 0x10000 in pages
    assert pages == sorted(pages)
    assert all(0x10000 <= p < 0x20000 for p in pages)


def test_back_reach_only_applies_to_a_page_aligned_cip():
    """The `cip - PAGE_SIZE` back-reach is compared against the *unaligned* address.

    The preceding page's base is therefore below the bound unless CIP is page-aligned, so in
    practice the window starts at CIP's own page. Nothing consumes the preceding page anyway:
    ContiguousSpan reads forward from cip, never behind it.
    Pinned here so the dead back-reach is not mistaken for intent.
    """
    unaligned = SelectWindowPages(ONE_REGION, 0x15005, PAGE_SIZE, CHUNK_SIZE)
    assert 0x14000 not in unaligned
    assert 0x15000 in unaligned

    aligned = SelectWindowPages(ONE_REGION, 0x15000, PAGE_SIZE, CHUNK_SIZE)
    assert 0x14000 in aligned


def test_window_is_bounded_by_chunk_size():
    # A region far larger than the window must not be walked into the view wholesale.
    huge = [(0x0, 0x8000000, 0x20)]
    pages = SelectWindowPages(huge, 0x4000000, PAGE_SIZE, CHUNK_SIZE)
    assert len(pages) <= (CHUNK_SIZE // PAGE_SIZE) + 2
    assert max(pages) <= 0x4000000 + CHUNK_SIZE


def test_window_empty_when_cip_is_unmapped():
    assert SelectWindowPages(ONE_REGION, 0x99000, PAGE_SIZE, CHUNK_SIZE) == []


def test_window_skips_regions_ending_before_cip():
    # Documents the retained asymmetry: regions are culled against cip, not cip - PAGE_SIZE,
    # so the page immediately below cip is not picked up from an earlier region.
    earlier = [(0xF000, 0x1000, 0x20), (0x10000, 0x10000, 0x20)]
    pages = SelectWindowPages(earlier, 0x10005, PAGE_SIZE, CHUNK_SIZE)
    assert 0xF000 not in pages


def test_assemble_returns_bytes_from_cip():
    buffers = {0x10000: bytes(range(256)) * 16}
    data = ContiguousSpan(buffers, 0x10010, PAGE_SIZE, PAGE_SIZE)
    assert data[:4] == buffers[0x10000][0x10:0x14]


def test_assemble_spans_two_adjacent_pages():
    buffers = {0x10000: b"\xaa" * PAGE_SIZE, 0x11000: b"\xbb" * PAGE_SIZE}
    data = ContiguousSpan(buffers, 0x10FFE, PAGE_SIZE, PAGE_SIZE)
    assert len(data) == PAGE_SIZE
    assert data[:2] == b"\xaa\xaa"
    assert data[2:4] == b"\xbb\xbb"


def test_assemble_refuses_when_cip_page_missing():
    """Regression: a later page's bytes must never be decoded as if they began at CIP."""
    buffers = {0x11000: b"\xbb" * PAGE_SIZE}
    assert ContiguousSpan(buffers, 0x10005, PAGE_SIZE, PAGE_SIZE) == b""


def test_assemble_refuses_when_cip_page_too_short_to_reach_cip():
    buffers = {0x10000: b"\xaa" * 0x100}
    assert ContiguousSpan(buffers, 0x10500, PAGE_SIZE, PAGE_SIZE) == b""


def test_assemble_stops_at_a_hole_left_by_a_truncated_region():
    """Regression: a region ending mid-page leaves a gap; bytes past it would be mislabelled."""
    buffers = {0x10000: b"\xaa" * 0x500, 0x11000: b"\xbb" * PAGE_SIZE}
    data = ContiguousSpan(buffers, 0x10000, PAGE_SIZE, PAGE_SIZE)
    assert data == b"\xaa" * 0x500


def test_assemble_ignores_pages_outside_the_hot_range():
    buffers = {0x10000: b"\xaa" * PAGE_SIZE, 0x40000: b"\xcc" * PAGE_SIZE}
    data = ContiguousSpan(buffers, 0x10000, PAGE_SIZE, PAGE_SIZE)
    assert data == b"\xaa" * PAGE_SIZE


def test_assemble_empty_cache():
    assert ContiguousSpan({}, 0x10005, PAGE_SIZE, PAGE_SIZE) == b""


def test_distant_pages_evicts_only_beyond_the_keep_span():
    cip = 0x100000
    near = PageBase(cip, PAGE_SIZE) + KEEP_PAGES * PAGE_SIZE
    far = near + PAGE_SIZE
    buffered = [PageBase(cip, PAGE_SIZE), near, far, 0x10000]
    evicted = DistantPages(buffered, cip, PAGE_SIZE, KEEP_PAGES)
    assert far in evicted
    assert 0x10000 in evicted
    assert near not in evicted
    assert PageBase(cip, PAGE_SIZE) not in evicted


def test_retained_cache_is_bounded():
    cip = 0x100000
    buffered = [i * PAGE_SIZE for i in range(1, 512)]
    kept = [p for p in buffered if p not in set(DistantPages(buffered, cip, PAGE_SIZE, KEEP_PAGES))]
    assert len(kept) <= 2 * KEEP_PAGES + 1


def LinearFindRegion(pageMap, addr):
    """The pre-bisect implementation, kept as the reference for the equivalence test."""
    for base, size, prot in pageMap:
        if base <= addr < base + size:
            return base, size, prot

    return None


def test_find_region_hits_inside_and_misses_outside():
    assert FindRegion(ONE_REGION, 0x10000) == (0x10000, 0x10000, 0x20)
    assert FindRegion(ONE_REGION, 0x1FFFF) == (0x10000, 0x10000, 0x20)
    assert FindRegion(ONE_REGION, 0x20000) is None
    assert FindRegion(ONE_REGION, 0xFFFF) is None
    assert FindRegion([], 0x10000) is None


def test_find_region_matches_the_linear_scan_it_replaced():
    pageMap = sorted(
        [
            (0x10000, 0x2000, 0x20),
            (0x12000, 0x1000, 0x04),
            (0x40000, 0x10000, 0x20),
            (0x400000, 0x1000, 0x02),
        ]
    )
    probes = [0x0, 0xFFFF, 0x10000, 0x11FFF, 0x12000, 0x12FFF, 0x13000, 0x3FFFF, 0x40000, 0x4FFFF, 0x400FFF, 0x500000]
    for addr in probes:
        assert FindRegion(pageMap, addr) == LinearFindRegion(pageMap, addr), hex(addr)


def test_find_region_ignores_gaps_between_regions():
    pageMap = [(0x10000, 0x1000, 0x20), (0x30000, 0x1000, 0x20)]
    assert FindRegion(pageMap, 0x20000) is None


def test_page_changed_is_pure():
    hashes = {}
    data = b"\xaa" * 16
    assert PageChanged(hashes, 0x10000, data) is True
    # Calling again must give the same answer: the old version recorded as it went, so using
    # it as a filter predicate made the result depend on the call count.
    assert PageChanged(hashes, 0x10000, data) is True
    assert hashes == {}

    hashes[0x10000] = PageHash(data)
    assert PageChanged(hashes, 0x10000, data) is False
    assert PageChanged(hashes, 0x10000, b"\xbb" * 16) is True


def test_page_changed_handles_missing_data():
    assert PageChanged({}, 0x10000, None) is False


class Inst:
    """Stand-in for DecodedInstruction, which lives behind the wx-importing modules."""

    def __init__(self, address, text="nop"):
        self.address = address
        self.text = text

    def __eq__(self, other):
        return (self.address, self.text) == (other.address, other.text)

    def __repr__(self):
        return f"Inst({self.address:#x})"


def test_contiguous_span_extends_past_one_page():
    buffers = {0x10000: b"\xaa" * PAGE_SIZE, 0x11000: b"\xbb" * PAGE_SIZE, 0x12000: b"\xcc" * PAGE_SIZE}
    data = ContiguousSpan(buffers, 0x10000, PAGE_SIZE, CHUNK_SIZE)
    assert len(data) == 3 * PAGE_SIZE


def test_contiguous_span_respects_max_bytes():
    buffers = {0x10000 + i * PAGE_SIZE: b"\xaa" * PAGE_SIZE for i in range(16)}
    data = ContiguousSpan(buffers, 0x10000, PAGE_SIZE, CHUNK_SIZE)
    assert len(data) == CHUNK_SIZE


def test_contiguous_span_stops_at_a_gap():
    buffers = {0x10000: b"\xaa" * PAGE_SIZE, 0x12000: b"\xcc" * PAGE_SIZE}
    data = ContiguousSpan(buffers, 0x10000, PAGE_SIZE, CHUNK_SIZE)
    assert len(data) == PAGE_SIZE


def test_contiguous_span_refuses_without_the_cip_page():
    buffers = {0x11000: b"\xbb" * PAGE_SIZE}
    assert ContiguousSpan(buffers, 0x10005, PAGE_SIZE, CHUNK_SIZE) == b""


def test_pages_of_span():
    assert PagesOfSpan(0x10000, 1, PAGE_SIZE) == [0x10000]
    assert PagesOfSpan(0x10000, PAGE_SIZE, PAGE_SIZE) == [0x10000]
    assert PagesOfSpan(0x10000, PAGE_SIZE + 1, PAGE_SIZE) == [0x10000, 0x11000]
    assert PagesOfSpan(0x10FFF, 2, PAGE_SIZE) == [0x10000, 0x11000]
    assert PagesOfSpan(0x10000, 0, PAGE_SIZE) == []


def test_bound_instructions_keeps_only_the_window():
    cip = 0x100000
    insts = [Inst(cip - 0x20000), Inst(cip - 0x10), Inst(cip), Inst(cip + 0x10), Inst(cip + 0x20000)]
    kept = BoundInstructions(insts, cip, 0x1000)
    assert [i.address for i in kept] == [cip - 0x10, cip, cip + 0x10]


def test_bound_instructions_keeps_pinned_addresses():
    """Back history, breakpoints and patches must survive eviction or Esc/Back breaks."""
    cip = 0x100000
    far = cip - 0x80000
    insts = [Inst(far), Inst(cip)]
    assert [i.address for i in BoundInstructions(insts, cip, 0x1000)] == [cip]
    assert [i.address for i in BoundInstructions(insts, cip, 0x1000, {far})] == [far, cip]


def test_common_prefix_length_identical_streams():
    a = [Inst(0x10), Inst(0x12), Inst(0x14)]
    b = [Inst(0x10), Inst(0x12), Inst(0x14)]
    assert CommonPrefixLength(a, b) == 3


def test_common_prefix_length_shared_head():
    a = [Inst(0x10), Inst(0x12), Inst(0x14)]
    b = [Inst(0x10), Inst(0x12), Inst(0x99)]
    assert CommonPrefixLength(a, b) == 2


def test_common_prefix_length_growth_and_empty():
    a = [Inst(0x10)]
    b = [Inst(0x10), Inst(0x12)]
    assert CommonPrefixLength(a, b) == 1
    assert CommonPrefixLength([], b) == 0
    assert CommonPrefixLength(a, []) == 0


def test_stepping_leaves_the_rendered_stream_unchanged():
    """The step fast path: same instructions, split at a new CIP, so no row changes."""
    stream = [Inst(0x1000), Inst(0x1002), Inst(0x1006), Inst(0x100A)]
    cip = 0x1002
    prefix = BoundInstructions([i for i in stream if i.address < cip], cip, 0x1000)
    rebuilt = prefix + [i for i in stream if i.address >= cip]
    assert CommonPrefixLength(stream, rebuilt) == len(stream)


def test_covers_address_detects_region_change():
    assert CoversAddress([0x10000], 0x10FFF, PAGE_SIZE)
    assert not CoversAddress([0x10000], 0x11000, PAGE_SIZE)
    assert not CoversAddress([], 0x10000, PAGE_SIZE)
