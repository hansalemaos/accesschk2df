# Automating the retrieval and analysis of access information using accesschk.exe


## pip install accesschk2df


#### Tested against Windows 10 / Python 3.10 / Anaconda 3

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



```python
df = get_accesschk_df()
# print(df[:3].to_string())
#    aa_pid       aa_exe aa_rights                      aa_path
# 0     592    lsass.exe        RW           NT-AUTORITT\SYSTEM
# 1     592    lsass.exe        RW  VORDEFINIERT\Administrators
# 2      84  svchost.exe         R  VORDEFINIERT\Administrators
```	