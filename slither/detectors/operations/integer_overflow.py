from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IntegerOverflow(AbstractDetector):
    """
    Detect Integer_overflow
    """

    ARGUMENT = "integer-overflow"  # slither will launch the detector with slither.py --mydetector
    HELP = "integer_overflow (detector example)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/trailofbits/slither/wiki/Adding-a-new-detector"
    WIKI_TITLE = "Integer_overflow example"
    WIKI_DESCRIPTION = "integer_overflow example"
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."

    def _detect(self):
        results = []

        for contract in self.slither.contracts_derived:
            # Check if a function has 'backdoor' in its name
            for f in contract.functions:
                if "safemath.sol" not in f.data:
                    if "+" in f.data or "-" in f.data or "*" in f.data:
                        # Info to be printed
                        info = ["integer_overflow found in ", f, "\n"]

                        # Add the result in result
                        res = self.generate_result(info)

                        results.append(res)

        return results
