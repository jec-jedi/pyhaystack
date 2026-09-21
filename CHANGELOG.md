# Changelog

## 4.3.0 - 2026-09-21

- SkySpark SCRAM sessions send `Attest-Key` when issued and omit cookies on
  grid POSTs so `pointWrite` is not rejected with
  `400 Attest-Key header required`.

## 4.2.0 - 2026-09-16

- Added Zinc POST point writes to the SCRAM SkySpark session.

## 4.1.0 - 2026-07-27

- Added explicit opt-in legacy TLS support and `ssl.SSLContext` passthrough.
