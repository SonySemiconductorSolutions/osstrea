""" A module checking packages in the SBOM agains the databases. """
from __future__ import annotations

import multiprocessing

from typing import Any, TYPE_CHECKING

from . import sbom_data
from . import database
from . import flowchart
if TYPE_CHECKING:
    from . import package

def _check_single_pkg(
        value:tuple[
            package.Pkg,
            database.Database,
            flowchart.FlowChart
        ]
    ) -> dict[str, package.Pkg|list[flowchart.CheckResult]]:
    pkg, db, fc = value
    results = fc.check_pkg(pkg, db)

    return {'pkg':pkg, 'results':results}

def check_packages(
        sbom:sbom_data.SBOMData,
        db:database.Database,
        fc:flowchart.FlowChart,
        *,
        processes:int|None=None
    ) -> list[dict[str, package.Pkg|list[flowchart.CheckResult]]]:
    """ Check packages in the SBOM against the databases. """
    if not isinstance(sbom, sbom_data.SBOMData):
        raise TypeError('The argument `sbom` must be an instance of `sbom_data.SBOMData`.')
    if not isinstance(db, database.Database):
        raise TypeError('The argument `db` must be an instance of `database.Database`.')
    if not isinstance(fc, flowchart.FlowChart):
        raise TypeError('The argument `fc` must be an instance of `flowchart.FlowChart`.')

    # NOTE: The optimal value here depends on the environment.
    # FIXME: Internet Connection Failed when processes > 4.
    if not isinstance(processes, int):
        processes = multiprocessing.cpu_count()
    if processes == 1:
        return [_check_single_pkg((pkg, db, fc)) for pkg in sbom.packages]
    else:
        with multiprocessing.Pool(processes=processes) as pool:
            values = [(pkg, db, fc) for pkg in sbom.packages]
            results = pool.map(_check_single_pkg, values)
        return results

class ResultAnalyzer:
    """ Class to analyze results"""
    def __init__(self, search_results:list[dict[str, Any]]):
        self.search_results = search_results
        attributes = flowchart.PkgAttributeList().attributes
        self.flowchart = flowchart.FlowChart(attributes)

    def analyze_results(self) -> list[dict[str, Any]]:
        """ Return the appropriate category and information for each package """
        analyzed_packages:list[dict[str, Any]] = []
        for pkg_result in self.search_results:
            analyzed_pkg:list[dict[str, Any]] = []
            pkg:package.Pkg = pkg_result['pkg']
            check_results:list[flowchart.CheckResult] = pkg_result['results']
            for result in check_results:
                analyzed_pkg.append({
                    'search_result':result,
                    'category':result.category,
                    'info':self.flowchart.output(result)})
            analyzed_packages.append({'pkg':pkg, 'results':analyzed_pkg})
        return analyzed_packages

    def statistics(self) -> list[tuple[str, int]]:
        """ Return statistics for the results """
        class Counts:
            def __init__(self):
                self.data:dict[str, int] = {}
                self.attribute_nums:dict[str, int] = {}

            def count(self, result:flowchart.CheckResult) -> None:
                if result.category not in self.data:
                    self.data[result.category] = 0
                    self.attribute_nums[result.category] = result.pkg_attribute.get_num()
                if result.conclusion:
                    self.data[result.category] += 1

            def sorted(self) -> list[tuple[str, int]]:
                return sorted(list(self.data.items()), key=lambda result: self.attribute_nums[result[0]])

        counts = Counts()
        for pkg_result in self.search_results:
            check_results:list[flowchart.CheckResult] = pkg_result['results']
            for result in check_results:
                counts.count(result)
        return counts.sorted()
