import subprocess
from a_pandas_ex_horizontal_explode import pd_add_horizontal_explode
from getfilenuitkapython import get_filepath
import pandas as pd

pd_add_horizontal_explode()
import re as regex
from multisubprocess import multi_subprocess

startupinfo = subprocess.STARTUPINFO()
startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
startupinfo.wShowWindow = subprocess.SW_HIDE
creationflags = subprocess.CREATE_NO_WINDOW
invisibledict = {
    "startupinfo": startupinfo,
    "creationflags": creationflags,
    "start_new_session": True,
}
stringsexe = get_filepath("accesschk.exe")


def get_accesschk_df() -> pd.DataFrame:
    """
    Individuals or organizations working with access control and security configurations can benefit from using this Python
    module by automating the retrieval and analysis of access information using accesschk.exe
    and leveraging the flexibility and functionality of Python and pandas for further data processing and analysis.

    accesschk.exe is a command-line tool developed by Microsoft that is used to view and analyze the security
    settings and access permissions of various system resources, such as files, directories, registry keys, services,
    and more. It provides detailed information about access control lists (ACLs) and user privileges for specific resources.

    This module utilizes the accesschk.exe tool to retrieve access information and convert it into a pandas DataFrame.
    By using this module, individuals or organizations working with access control and security configurations can
    programmatically access and analyze access permissions in a more convenient and automated manner.

    Advantages of using this Python module include:

    Automation:
    The module allows for the automation of accesschk.exe functionality through Python code,
    enabling users to retrieve and process access information programmatically.

    Integration:
    The module integrates the functionality of accesschk.exe with pandas, a popular data manipulation library in Python.
    This enables users to easily perform further data analysis, transformations, and visualizations on the access
    information using pandas' extensive capabilities.

    Flexibility:
    Python provides a wide range of data analysis and processing libraries, making it easier to integrate the access
    information with other data sources and perform complex analyses or combine it with additional security-related tasks.

    Reproducibility:
    By using Python code, users can document and reproduce their access information retrieval and analysis workflows.
    This is especially useful for auditing, troubleshooting, or creating reports related to access permissions.
    """

    allqueries = [
        [
            stringsexe,
            "-p",
            "*",
            "-s",
            "-accepteula",
            "-nobanner",
            "-q",
        ]
    ]

    res = multi_subprocess(
        allqueries,
        byteinput=b"",
        shell=False,
        close_fds=False,
        start_new_session=True,
        invisible=True,
        kill_all_at_end=True,
        blockbatch=False,
    )

    results = [
        [x[0][-1], x[1]["stdoutready"]]
        for x in res.items()
        if x[1]["returncode"] == 0 and x[1]["stdoutready"].strip()
    ]

    df = pd.DataFrame(
        [
            (
                h := [
                    regex.sub(
                        r"QQQQXXXX\s*", "\n", v.decode("utf-8", "ignore").strip()
                    ).split(maxsplit=1)
                    for v in regex.split(rb"QQQQXXXX(?=\s+\b[RW]+\b)", x)
                ],
                h[0],
                h[1:],
            )
            for x in regex.findall(
                rb"QQQQXXXX\[\d+\].*?(?=QQQQXXXX\[\d+\])",
                b"QQQQXXXX".join(results[-1][-1].splitlines()),
            )
            if b"Error opening" not in x
        ]
    ).drop(columns=0)
    df = (
        pd.concat([df[1].ds_horizontal_explode("proc", concat=False), df[2]], axis=1)
        .explode(2)
        .ds_horizontal_explode(2)
        .drop(columns=2)
        .reset_index(drop=True)
    )
    df.columns = ["aa_pid", "aa_exe", "aa_rights", "aa_path"]
    df.aa_pid = df.aa_pid.str.strip("[] ").astype("Int64")
    for col in ["aa_exe", "aa_rights", "aa_path"]:
        try:
            df[col] = df[col].astype("string")
        except Exception:
            pass

    return df



