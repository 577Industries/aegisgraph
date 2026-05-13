"""Deeplink-family PolyDiff Extended tests (T-M2.4).

Mirror of tests/polydiff_extended/opengraph/ for the deeplink family per
Asemarefactor.md §"Engine 1: PolyDiff Extended" module-layout pattern
("NEW — Android intent URI + iOS universal link"). The deeplink family
covers Android `intent://` URI parsing, iOS universal links / custom
schemes, and WHATWG-URL generic fallback so disagreements among them
surface implicit-export, origin-confusion, open-redirect, and path-
traversal classes by hash-pinned anchored cases.
"""
