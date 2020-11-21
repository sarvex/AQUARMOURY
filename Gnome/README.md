# Gnome
[![](https://img.shields.io/badge/Category-Defense%20Evasion-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-C%20%2f%20C++%20%2f%20Python3-E5A505?style=flat-square)]()

## Introduction
`Gnome` is a module to load your signed driver stealthily. The driver is extracted from the `Gnome` loader, dropped to disk and loaded using `NtLoadDriver` instead of the service creation driver loading which can be noisy. It can be used to drop'n'load your signed rootkit in the target environment. It can also be used to load a vulnerable signed driver to execute Ring-0 code for exploitation.
