import binascii
import logging
import os

import yara

from .path_utils import path_exists

log = logging.getLogger(__name__)


class YaraProcessor(object):
    yara_error = {
        "1": "ERROR_INSUFFICIENT_MEMORY",
        "2": "ERROR_COULD_NOT_ATTACH_TO_PROCESS",
        "3": "ERROR_COULD_NOT_OPEN_FILE",
        "4": "ERROR_COULD_NOT_MAP_FILE",
        "6": "ERROR_INVALID_FILE",
        "7": "ERROR_CORRUPT_FILE",
        "8": "ERROR_UNSUPPORTED_FILE_VERSION",
        "9": "ERROR_INVALID_REGULAR_EXPRESSION",
        "10": "ERROR_INVALID_HEX_STRING",
        "11": "ERROR_SYNTAX_ERROR",
        "12": "ERROR_LOOP_NESTING_LIMIT_EXCEEDED",
        "13": "ERROR_DUPLICATED_LOOP_IDENTIFIER",
        "14": "ERROR_DUPLICATED_IDENTIFIER",
        "15": "ERROR_DUPLICATED_TAG_IDENTIFIER",
        "16": "ERROR_DUPLICATED_META_IDENTIFIER",
        "17": "ERROR_DUPLICATED_STRING_IDENTIFIER",
        "18": "ERROR_UNREFERENCED_STRING",
        "19": "ERROR_UNDEFINED_STRING",
        "20": "ERROR_UNDEFINED_IDENTIFIER",
        "21": "ERROR_MISPLACED_ANONYMOUS_STRING",
        "22": "ERROR_INCLUDES_CIRCULAR_REFERENCE",
        "23": "ERROR_INCLUDE_DEPTH_EXCEEDED",
        "24": "ERROR_WRONG_TYPE",
        "25": "ERROR_EXEC_STACK_OVERFLOW",
        "26": "ERROR_SCAN_TIMEOUT",
        "27": "ERROR_TOO_MANY_SCAN_THREADS",
        "28": "ERROR_CALLBACK_ERROR",
        "29": "ERROR_INVALID_ARGUMENT",
        "30": "ERROR_TOO_MANY_MATCHES",
        "31": "ERROR_INTERNAL_FATAL_ERROR",
        "32": "ERROR_NESTED_FOR_OF_LOOP",
        "33": "ERROR_INVALID_FIELD_NAME",
        "34": "ERROR_UNKNOWN_MODULE",
        "35": "ERROR_NOT_A_STRUCTURE",
        "36": "ERROR_NOT_INDEXABLE",
        "37": "ERROR_NOT_A_FUNCTION",
        "38": "ERROR_INVALID_FORMAT",
        "39": "ERROR_TOO_MANY_ARGUMENTS",
        "40": "ERROR_WRONG_ARGUMENTS",
        "41": "ERROR_WRONG_RETURN_TYPE",
        "42": "ERROR_DUPLICATED_STRUCTURE_MEMBER",
        "43": "ERROR_EMPTY_STRING",
        "44": "ERROR_DIVISION_BY_ZERO",
        "45": "ERROR_REGULAR_EXPRESSION_TOO_LARGE",
        "46": "ERROR_TOO_MANY_RE_FIBERS",
        "47": "ERROR_COULD_NOT_READ_PROCESS_MEMORY",
        "48": "ERROR_INVALID_EXTERNAL_VARIABLE_TYPE",
        "49": "ERROR_REGULAR_EXPRESSION_TOO_COMPLEX",
    }

    def __init__(self, yara_root="yara"):
        self.yara_root = yara_root
        self.yara_rules = {}
        self.init_yara()

    def _yara_encode_string(self, yara_string):
        # Beware, spaghetti code ahead.
        if not isinstance(yara_string, bytes):
            return yara_string
        try:
            new = yara_string.decode()
        except UnicodeDecodeError:
            # yara_string = binascii.hexlify(yara_string.lstrip("uU")).upper()
            yara_string = binascii.hexlify(yara_string).upper()
            yara_string = b" ".join(
                yara_string[i : i + 2] for i in range(0, len(yara_string), 2)
            )
            new = f"{{ {yara_string.decode()} }}"

        return new

    def init_yara(self):
        log.debug("Initializing Yara...")
        categories = [
            name
            for name in os.listdir(self.yara_root)
            if os.path.isdir(os.path.join(self.yara_root, name))
        ]

        # Loop through all categories.
        for category in categories:
            rules, indexed = {}, []
            # Check if there is a directory for the given category.
            category_root = os.path.join(self.yara_root, category)
            if not path_exists(category_root):
                log.warning("Missing Yara directory: %s?", category_root)
                continue

            for filename in os.listdir(category_root):
                if not filename.endswith((".yar", ".yara")):
                    continue
                filepath = os.path.join(category_root, filename)
                rules[f"rule_{category}_{len(rules)}"] = filepath
                indexed.append(filename)

            # Need to define each external variable that will be used in the
            # future. Otherwise, Yara will complain.
            externals = {"filename": ""}

            while True:
                try:
                    self.yara_rules[category] = yara.compile(
                        filepaths=rules, externals=externals
                    )
                    break
                except yara.SyntaxError as e:
                    bad_rule = f"{str(e).split('.yar', 1)[0]}.yar"
                    log.debug(
                        "Trying to disable rule: %s. Can't compile it. Ensure that your YARA is properly installed.",
                        bad_rule,
                    )
                    if os.path.basename(bad_rule) not in indexed:
                        break
                    for k, v in rules.items():
                        if v == bad_rule:
                            del rules[k]
                            indexed.remove(os.path.basename(bad_rule))
                            log.error(
                                "Can't compile YARA rule: %s. Maybe is bad yara but can be missing YARA's module.",
                                bad_rule,
                            )
                            break
                except yara.Error as e:
                    log.error(
                        "There was a syntax error in one or more Yara rules: %s", e
                    )
                    break

            indexed = sorted(indexed)
            for entry in indexed:
                if (category, entry) == indexed[-1]:
                    log.debug("\t `-- %s %s", category, entry)
                else:
                    log.debug("\t |-- %s %s", category, entry)

    def get_yara(self, file_path, category="CAPE", externals=None):
        """Get Yara signatures matches.
        @return: matched Yara signatures.
        """
        file_path_ansii = (
            file_path if isinstance(file_path, str) else file_path.decode()
        )
        results = []
        if not os.path.getsize(file_path):
            return results

        try:
            results, rule = [], self.yara_rules[category]
            for match in rule.match(file_path_ansii, externals=externals):
                strings = []
                addresses = {}
                for yara_string in match.strings:
                    for x in yara_string.instances:
                        y_string = self._yara_encode_string(x.matched_data)
                        if y_string not in strings:
                            strings.append(y_string)
                        addresses.update({yara_string.identifier.strip("$"): x.offset})
                results.append(
                    {
                        "name": match.rule,
                        "meta": match.meta,
                        "strings": strings,
                        "addresses": addresses,
                    }
                )
        except Exception as e:
            errcode = str(e).rsplit(maxsplit=1)[-1]
            if errcode in self.yara_error:
                log.exception(
                    "Unable to match Yara signatures for %s: %s",
                    file_path,
                    self.yara_error[errcode],
                )

            else:
                log.exception(
                    "Unable to match Yara signatures for %s: unknown code %s",
                    file_path,
                    errcode,
                )

        return results
