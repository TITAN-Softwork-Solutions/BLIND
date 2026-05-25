# BLIND Internal Component License

Copyright (c) TITAN Softwork Solutions. All rights reserved.

BLIND is a Titan internal security research and validation component for the BLIND user-mode runtime. It is licensed only for controlled development, testing, validation, and defensive research under Titan-approved use.

## Authorized Use

You may use BLIND only to:

- test Titan-owned or operator-owned processes and lab systems;
- validate BLIND user-mode EDR-sensor telemetry behavior without a kernel driver;
- develop internal detection, analysis, QA, and regression tests;
- run the included standalone runner against child test processes created by the runner.

## Prohibited Use

You may not use BLIND to:

- access, monitor, alter, or instrument systems without explicit authorization;
- evade detection, conceal unauthorized activity, persist in a third-party environment, or bypass security controls;
- deliver malware, credential theft tooling, payload loaders, or unauthorized surveillance;
- provide BLIND to third parties except under a written Titan authorization that preserves these controls.

## DSGL And Export-Control Notice

BLIND may be subject to Australian Defence and Strategic Goods List (DSGL), export-control, sanctions, and dual-use restrictions. Do not export, re-export, transfer, publish, or provide access to BLIND, its source, binaries, documentation, or derived artifacts except under Titan-approved controls and all applicable law.

Operators are responsible for confirming that each use, transfer, demonstration, and build artifact remains inside approved DSGL/export-control boundaries.

## Secure Use Policy

BLIND must be used with least privilege, against owned targets, and with auditability enabled where practical. Test artifacts should be stored in controlled repositories, signed where required, and deleted from unmanaged hosts after testing.

The standalone runner intentionally supports only child processes it creates. Do not add arbitrary-PID attach, persistence, stealth loading, or uncontrolled remote deployment paths without a formal Titan security review.

## No Warranty

BLIND is provided for internal testing as-is. TITAN Softwork Solutions disclaims all warranties and is not liable for misuse, unauthorized deployment, or regulatory non-compliance.
