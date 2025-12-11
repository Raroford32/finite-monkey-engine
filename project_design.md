1. ERC Compliance and Token Standards
EIP/ERC Compliance Requirements
EIP-712 Implementation:

Typed signatures for setUserPositionManager intents on Spoke
All intents processed through signature gateways
Validation Standard: EIP violations must be at least medium severity to be valid
ERC-20 Token Requirements:

Only explicitly whitelisted ERC20 tokens are accepted
Must fully comply with ERC20 standard, no non-standard hooks
Explicitly Prohibited:
ERC777 tokens (with callback mechanisms)
Fee-on-transfer tokens
Rebasing tokens
Reflection tokens
Any tokens with balance mutation side effects

3. Configuration Hard Limits
Governance-Configurable Parameters with Hard Upper Bounds
Although governance roles are trusted, the protocol enforces the following limits at the code level:

1. Asset Precision Limits
MIN_ALLOWED_UNDERLYING_DECIMALS ≤ asset decimals ≤ MAX_ALLOWED_UNDERLYING_DECIMALS

Assets outside this range cannot be listed

2. Collateral Risk Score (collateralFactor)
0 ≤ collateralFactor ≤ MAX_ALLOWED_RISK (protocol-defined upper limit)

Prevents governance from setting risk scores beyond the protocol's upper limit

3. Liquidation Parameter Limits
Maximum Liquidation Bonus:

maxLiquidationBonus ≥ PROTOCOL_MIN_LIQUIDATION_BONUS

Liquidation Bonus × Risk Score Product:

maxLiquidationBonus × collateralFactor ≤ GLOBAL_UPPER_LIMIT

Liquidation Fee:

liquidationFee ≤ PROTOCOL_MAX_LIQUIDATION_FEE

Configuration Trust Assumptions
Governance Parameters:

Privileged roles (Aave DAO and governance-approved executors) are considered honest actors
Configuration errors are considered out of scope for audits
Most configuration values without explicit limits rely on governance processes rather than on-chain caps
External Protocol Integration:
Chainlink price feeds are considered trusted
Whitelisted collateral assets are considered trusted
These dependencies behave consistently and do not introduce arbitrary semantic changes

Trust Boundary Model (Hub ↔ Spoke)
Asymmetric Trust Architecture:

Hub (Authority Layer):

Serves as the single source of truth
Maintains global state and accounting
Enforces invariants
Immutable core
Spoke (Execution Layer):

Governance-Permissioned: Only governance-explicitly authorized Spokes can call Hub modifiers
Considered Trusted: Spokes are assumed to operate legitimately after governance approval
Scope of Responsibilities:
Determines source/destination addresses for ERC20 transfers between users and Hub
Controls timing of user premium accounting
Manages donations within the Spoke
Operates under global invariants enforced by the Hub
Subject to per-Spoke caps/flags
