"""
Economic Modeling and Game Theory Engine

This module provides economic analysis and game-theoretic reasoning
to discover profit-motivated exploits and MEV opportunities.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
from scipy.optimize import linprog, minimize
import networkx as nx

logger = logging.getLogger(__name__)


class EconomicPrimitive(Enum):
    """Economic primitives in DeFi"""
    ARBITRAGE = "arbitrage"
    SANDWICH = "sandwich"
    LIQUIDATION = "liquidation"
    MANIPULATION = "manipulation"
    FRONT_RUNNING = "front_running"
    BACK_RUNNING = "back_running"
    JIT_LIQUIDITY = "jit_liquidity"
    GOVERNANCE_BUYING = "governance_buying"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FLASH_LOAN_ARBITRAGE = "flash_loan_arbitrage"


@dataclass
class EconomicOpportunity:
    """Represents an economic opportunity for profit"""
    id: str
    type: EconomicPrimitive
    profit_estimate: float
    capital_required: float
    
    # Execution details
    target_protocol: str
    target_pools: List[str] = field(default_factory=list)
    execution_path: List[Dict[str, Any]] = field(default_factory=list)
    
    # Risk assessment
    success_probability: float = 1.0
    competition_level: float = 0.0  # 0 = no competition, 1 = high competition
    mev_protected: bool = False
    
    # Timing
    time_sensitive: bool = False
    optimal_block: Optional[int] = None
    expiry_block: Optional[int] = None


@dataclass
class MarketState:
    """Current market state across protocols"""
    block_number: int
    timestamp: int
    
    # Prices across venues
    prices: Dict[str, Dict[str, float]] = field(default_factory=dict)  # venue -> token -> price
    
    # Liquidity
    liquidity: Dict[str, float] = field(default_factory=dict)  # pool -> liquidity
    
    # Volume
    volume_24h: Dict[str, float] = field(default_factory=dict)
    
    # Gas prices
    base_fee: float = 20.0
    priority_fee: float = 2.0
    
    # MEV landscape
    pending_transactions: List[Dict[str, Any]] = field(default_factory=list)
    mempool_value: float = 0.0


@dataclass
class GameTheoreticScenario:
    """Game theoretic analysis of multi-agent scenarios"""
    players: List[str]
    strategies: Dict[str, List[str]]
    payoff_matrix: np.ndarray
    nash_equilibria: List[Tuple[str, ...]]
    dominant_strategies: Dict[str, Optional[str]]


class EconomicModelingEngine:
    """
    Economic modeling and game theory engine for exploit discovery
    
    Analyzes economic incentives, game theory, and MEV to find
    profitable attack vectors and manipulation opportunities.
    """
    
    def __init__(self):
        """Initialize the economic modeling engine"""
        self.market_graph = nx.DiGraph()
        self.liquidity_map = {}
        self.arbitrage_paths = []
        self.mev_opportunities = []
        
        logger.info("Economic Modeling Engine initialized")
    
    async def analyze_economic_incentives(
        self,
        protocol_model: Dict[str, Any],
        market_state: MarketState
    ) -> List[EconomicOpportunity]:
        """Analyze economic incentives for exploitation"""
        logger.info("Analyzing economic incentives...")
        
        opportunities = []
        
        # 1. Arbitrage opportunities
        arb_opps = await self._find_arbitrage_opportunities(
            protocol_model,
            market_state
        )
        opportunities.extend(arb_opps)
        
        # 2. Liquidation opportunities
        liq_opps = await self._find_liquidation_opportunities(
            protocol_model,
            market_state
        )
        opportunities.extend(liq_opps)
        
        # 3. MEV opportunities
        mev_opps = await self._find_mev_opportunities(
            protocol_model,
            market_state
        )
        opportunities.extend(mev_opps)
        
        # 4. Manipulation opportunities
        manip_opps = await self._find_manipulation_opportunities(
            protocol_model,
            market_state
        )
        opportunities.extend(manip_opps)
        
        # 5. Governance attacks
        gov_opps = await self._find_governance_opportunities(
            protocol_model,
            market_state
        )
        opportunities.extend(gov_opps)
        
        # Sort by profit potential
        opportunities.sort(key=lambda x: x.profit_estimate, reverse=True)
        
        return opportunities
    
    async def _find_arbitrage_opportunities(
        self,
        protocol_model: Dict[str, Any],
        market_state: MarketState
    ) -> List[EconomicOpportunity]:
        """Find arbitrage opportunities across venues"""
        opportunities = []
        
        # Build price graph
        self._build_price_graph(market_state)
        
        # Find negative cycles (arbitrage)
        try:
            negative_cycles = nx.negative_edge_cycle(
                self.market_graph,
                weight='weight'
            )
            
            for cycle in negative_cycles:
                profit = self._calculate_cycle_profit(cycle, market_state)
                
                if profit > 0:
                    opportunities.append(EconomicOpportunity(
                        id=f"arb_{len(opportunities)}",
                        type=EconomicPrimitive.ARBITRAGE,
                        profit_estimate=profit,
                        capital_required=self._estimate_capital_for_arb(cycle),
                        target_protocol="multi",
                        target_pools=cycle,
                        execution_path=self._build_arb_path(cycle),
                        time_sensitive=True
                    ))
                    
        except nx.NetworkXError:
            pass  # No negative cycles found
        
        # Cross-DEX arbitrage
        dex_arbs = await self._find_cross_dex_arbitrage(market_state)
        opportunities.extend(dex_arbs)
        
        return opportunities
    
    def _build_price_graph(self, market_state: MarketState):
        """Build graph of prices across venues"""
        self.market_graph.clear()
        
        for venue, prices in market_state.prices.items():
            for token_pair, price in prices.items():
                if '_' in token_pair:
                    token_a, token_b = token_pair.split('_')
                    
                    # Add edges for both directions
                    # Forward: A -> B
                    self.market_graph.add_edge(
                        f"{venue}:{token_a}",
                        f"{venue}:{token_b}",
                        weight=-np.log(price),  # Negative log for multiplicative weights
                        price=price,
                        venue=venue
                    )
                    
                    # Reverse: B -> A
                    self.market_graph.add_edge(
                        f"{venue}:{token_b}",
                        f"{venue}:{token_a}",
                        weight=-np.log(1/price),
                        price=1/price,
                        venue=venue
                    )
        
        # Add cross-venue edges (for transfers)
        venues = list(market_state.prices.keys())
        for token in self._get_all_tokens(market_state):
            for v1 in venues:
                for v2 in venues:
                    if v1 != v2:
                        # Small cost for transfers between venues
                        self.market_graph.add_edge(
                            f"{v1}:{token}",
                            f"{v2}:{token}",
                            weight=0.001,  # Transfer cost
                            price=1.0,
                            venue="transfer"
                        )
    
    def _get_all_tokens(self, market_state: MarketState) -> Set[str]:
        """Get all unique tokens from market state"""
        tokens = set()
        for prices in market_state.prices.values():
            for pair in prices.keys():
                if '_' in pair:
                    t1, t2 = pair.split('_')
                    tokens.add(t1)
                    tokens.add(t2)
        return tokens
    
    def _calculate_cycle_profit(
        self,
        cycle: List[str],
        market_state: MarketState
    ) -> float:
        """Calculate profit from arbitrage cycle"""
        initial_capital = 10000  # $10k starting capital
        current_amount = initial_capital
        
        for i in range(len(cycle)):
            current_node = cycle[i]
            next_node = cycle[(i + 1) % len(cycle)]
            
            edge_data = self.market_graph.get_edge_data(current_node, next_node)
            if edge_data:
                price = edge_data.get('price', 1.0)
                current_amount *= price * 0.997  # 0.3% fee
        
        profit = current_amount - initial_capital
        
        # Subtract gas costs
        gas_cost = len(cycle) * market_state.base_fee * 200000 / 1e9 * 2000  # Rough estimate
        
        return profit - gas_cost
    
    def _estimate_capital_for_arb(self, cycle: List[str]) -> float:
        """Estimate capital required for arbitrage"""
        # Simplified: use fixed amount that maximizes profit
        return 10000.0
    
    def _build_arb_path(self, cycle: List[str]) -> List[Dict[str, Any]]:
        """Build execution path for arbitrage"""
        path = []
        
        for i in range(len(cycle)):
            current = cycle[i]
            next_node = cycle[(i + 1) % len(cycle)]
            
            venue, token = current.split(':')
            next_venue, next_token = next_node.split(':')
            
            if venue == next_venue:
                # Swap within venue
                path.append({
                    'action': 'swap',
                    'venue': venue,
                    'from': token,
                    'to': next_token
                })
            else:
                # Transfer between venues
                path.append({
                    'action': 'transfer',
                    'token': token,
                    'from_venue': venue,
                    'to_venue': next_venue
                })
        
        return path
    
    async def _find_cross_dex_arbitrage(
        self,
        market_state: MarketState
    ) -> List[EconomicOpportunity]:
        """Find arbitrage between different DEXes"""
        opportunities = []
        
        # Compare prices across venues
        for token_pair in self._get_common_pairs(market_state):
            prices_by_venue = {}
            
            for venue, prices in market_state.prices.items():
                if token_pair in prices:
                    prices_by_venue[venue] = prices[token_pair]
            
            if len(prices_by_venue) >= 2:
                min_price = min(prices_by_venue.values())
                max_price = max(prices_by_venue.values())
                
                price_diff_pct = (max_price - min_price) / min_price * 100
                
                if price_diff_pct > 0.5:  # More than 0.5% difference
                    buy_venue = min(prices_by_venue, key=prices_by_venue.get)
                    sell_venue = max(prices_by_venue, key=prices_by_venue.get)
                    
                    profit = self._calculate_cross_dex_profit(
                        buy_venue,
                        sell_venue,
                        min_price,
                        max_price,
                        market_state
                    )
                    
                    if profit > 0:
                        opportunities.append(EconomicOpportunity(
                            id=f"cross_dex_{token_pair}",
                            type=EconomicPrimitive.ARBITRAGE,
                            profit_estimate=profit,
                            capital_required=10000,
                            target_protocol="multi",
                            target_pools=[buy_venue, sell_venue],
                            execution_path=[
                                {'action': 'buy', 'venue': buy_venue, 'pair': token_pair},
                                {'action': 'sell', 'venue': sell_venue, 'pair': token_pair}
                            ],
                            time_sensitive=True
                        ))
        
        return opportunities
    
    def _get_common_pairs(self, market_state: MarketState) -> Set[str]:
        """Get token pairs that exist across multiple venues"""
        pair_counts = {}
        
        for prices in market_state.prices.values():
            for pair in prices.keys():
                pair_counts[pair] = pair_counts.get(pair, 0) + 1
        
        return {pair for pair, count in pair_counts.items() if count >= 2}
    
    def _calculate_cross_dex_profit(
        self,
        buy_venue: str,
        sell_venue: str,
        buy_price: float,
        sell_price: float,
        market_state: MarketState
    ) -> float:
        """Calculate profit from cross-DEX arbitrage"""
        capital = 10000
        
        # Buy on cheaper venue
        amount_bought = capital / buy_price * 0.997  # 0.3% fee
        
        # Sell on expensive venue
        amount_sold = amount_bought * sell_price * 0.997  # 0.3% fee
        
        profit = amount_sold - capital
        
        # Gas costs (2 transactions)
        gas_cost = 2 * market_state.base_fee * 200000 / 1e9 * 2000
        
        return profit - gas_cost
    
    async def _find_liquidation_opportunities(
        self,
        protocol_model: Dict[str, Any],
        market_state: MarketState
    ) -> List[EconomicOpportunity]:
        """Find profitable liquidation opportunities"""
        opportunities = []
        
        # Check lending protocols
        if 'lending' in str(protocol_model.get('primitives', [])).lower():
            # Analyze positions at risk
            positions = await self._get_underwater_positions(protocol_model)
            
            for position in positions:
                liquidation_bonus = position.get('collateral_value', 0) * 0.05  # 5% bonus
                gas_cost = market_state.base_fee * 500000 / 1e9 * 2000
                
                profit = liquidation_bonus - gas_cost
                
                if profit > 0:
                    opportunities.append(EconomicOpportunity(
                        id=f"liq_{position.get('user')}",
                        type=EconomicPrimitive.LIQUIDATION,
                        profit_estimate=profit,
                        capital_required=position.get('debt_value', 0),
                        target_protocol=protocol_model.get('name', 'unknown'),
                        execution_path=[
                            {'action': 'liquidate', 'user': position.get('user')}
                        ],
                        time_sensitive=True
                    ))
        
        return opportunities
    
    async def _get_underwater_positions(
        self,
        protocol_model: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Get positions that can be liquidated"""
        # This would query actual protocol state
        # Simplified for demonstration
        return [
            {
                'user': '0xuser1',
                'collateral_value': 15000,
                'debt_value': 10000,
                'health_factor': 0.9
            }
        ]
    
    async def _find_mev_opportunities(
        self,
        protocol_model: Dict[str, Any],
        market_state: MarketState
    ) -> List[EconomicOpportunity]:
        """Find MEV opportunities in mempool"""
        opportunities = []
        
        # Analyze pending transactions
        for tx in market_state.pending_transactions:
            # Sandwich attacks
            if self._is_sandwichable(tx):
                sandwich_profit = self._calculate_sandwich_profit(tx, market_state)
                
                if sandwich_profit > 0:
                    opportunities.append(EconomicOpportunity(
                        id=f"sandwich_{tx.get('hash')}",
                        type=EconomicPrimitive.SANDWICH,
                        profit_estimate=sandwich_profit,
                        capital_required=self._estimate_sandwich_capital(tx),
                        target_protocol=tx.get('to'),
                        execution_path=[
                            {'action': 'frontrun', 'tx': tx.get('hash')},
                            {'action': 'wait', 'for': tx.get('hash')},
                            {'action': 'backrun', 'tx': tx.get('hash')}
                        ],
                        time_sensitive=True,
                        optimal_block=market_state.block_number + 1
                    ))
            
            # Front-running
            if self._is_frontrunnable(tx):
                frontrun_profit = self._calculate_frontrun_profit(tx, market_state)
                
                if frontrun_profit > 0:
                    opportunities.append(EconomicOpportunity(
                        id=f"frontrun_{tx.get('hash')}",
                        type=EconomicPrimitive.FRONT_RUNNING,
                        profit_estimate=frontrun_profit,
                        capital_required=0,
                        target_protocol=tx.get('to'),
                        execution_path=[
                            {'action': 'frontrun', 'tx': tx.get('hash')}
                        ],
                        time_sensitive=True,
                        optimal_block=market_state.block_number + 1
                    ))
        
        return opportunities
    
    def _is_sandwichable(self, tx: Dict[str, Any]) -> bool:
        """Check if transaction can be sandwiched"""
        # Look for large swaps
        return (tx.get('value', 0) > 10000 or 
                'swap' in str(tx.get('input', '')).lower())
    
    def _calculate_sandwich_profit(
        self,
        tx: Dict[str, Any],
        market_state: MarketState
    ) -> float:
        """Calculate profit from sandwich attack"""
        # Simplified calculation
        tx_value = tx.get('value', 0)
        
        if tx_value > 0:
            # Estimate price impact
            price_impact = tx_value / 1000000  # Rough estimate
            
            # Profit from price movement
            profit = tx_value * price_impact * 0.1
            
            # Subtract gas costs (3 transactions)
            gas_cost = 3 * market_state.priority_fee * 300000 / 1e9 * 2000
            
            return profit - gas_cost
        
        return 0
    
    def _estimate_sandwich_capital(self, tx: Dict[str, Any]) -> float:
        """Estimate capital needed for sandwich attack"""
        return tx.get('value', 0) * 2  # Need to move price significantly
    
    def _is_frontrunnable(self, tx: Dict[str, Any]) -> bool:
        """Check if transaction can be frontrun"""
        # Look for profitable operations
        return 'claim' in str(tx.get('input', '')).lower()
    
    def _calculate_frontrun_profit(
        self,
        tx: Dict[str, Any],
        market_state: MarketState
    ) -> float:
        """Calculate profit from frontrunning"""
        # Simplified - would analyze actual transaction
        return 100  # Fixed profit estimate
    
    async def _find_manipulation_opportunities(
        self,
        protocol_model: Dict[str, Any],
        market_state: MarketState
    ) -> List[EconomicOpportunity]:
        """Find price manipulation opportunities"""
        opportunities = []
        
        # Oracle manipulation
        if 'oracle' in str(protocol_model.get('primitives', [])).lower():
            oracle_manip = await self._analyze_oracle_manipulation(
                protocol_model,
                market_state
            )
            opportunities.extend(oracle_manip)
        
        # AMM manipulation
        if 'swapping' in str(protocol_model.get('primitives', [])).lower():
            amm_manip = await self._analyze_amm_manipulation(
                protocol_model,
                market_state
            )
            opportunities.extend(amm_manip)
        
        return opportunities
    
    async def _analyze_oracle_manipulation(
        self,
        protocol_model: Dict[str, Any],
        market_state: MarketState
    ) -> List[EconomicOpportunity]:
        """Analyze oracle manipulation opportunities"""
        opportunities = []
        
        # Check for spot price dependencies
        if self._uses_spot_price_oracle(protocol_model):
            # Calculate manipulation cost and profit
            manip_cost = 100000  # Cost to manipulate
            expected_profit = 500000  # Expected profit from exploitation
            
            if expected_profit > manip_cost:
                opportunities.append(EconomicOpportunity(
                    id="oracle_manip_spot",
                    type=EconomicPrimitive.ORACLE_MANIPULATION,
                    profit_estimate=expected_profit - manip_cost,
                    capital_required=manip_cost,
                    target_protocol=protocol_model.get('name', 'unknown'),
                    execution_path=[
                        {'action': 'manipulate_price', 'method': 'large_trade'},
                        {'action': 'exploit', 'target': 'lending'},
                        {'action': 'restore_price'}
                    ],
                    success_probability=0.8
                ))
        
        return opportunities
    
    def _uses_spot_price_oracle(self, protocol_model: Dict[str, Any]) -> bool:
        """Check if protocol uses spot price oracle"""
        # Simplified check
        return 'getPrice' in str(protocol_model)
    
    async def _analyze_amm_manipulation(
        self,
        protocol_model: Dict[str, Any],
        market_state: MarketState
    ) -> List[EconomicOpportunity]:
        """Analyze AMM manipulation opportunities"""
        opportunities = []
        
        # JIT liquidity attacks
        for pool in protocol_model.get('pools', []):
            if self._is_jit_profitable(pool, market_state):
                opportunities.append(EconomicOpportunity(
                    id=f"jit_{pool}",
                    type=EconomicPrimitive.JIT_LIQUIDITY,
                    profit_estimate=1000,
                    capital_required=100000,
                    target_protocol=protocol_model.get('name', 'unknown'),
                    target_pools=[pool],
                    execution_path=[
                        {'action': 'add_liquidity', 'pool': pool},
                        {'action': 'wait_for_trade'},
                        {'action': 'remove_liquidity', 'pool': pool}
                    ],
                    time_sensitive=True
                ))
        
        return opportunities
    
    def _is_jit_profitable(self, pool: str, market_state: MarketState) -> bool:
        """Check if JIT liquidity attack is profitable"""
        # Check volume and fees
        volume = market_state.volume_24h.get(pool, 0)
        return volume > 1000000  # High volume pool
    
    async def _find_governance_opportunities(
        self,
        protocol_model: Dict[str, Any],
        market_state: MarketState
    ) -> List[EconomicOpportunity]:
        """Find governance attack opportunities"""
        opportunities = []
        
        if 'governance' in str(protocol_model.get('primitives', [])).lower():
            # Check voting power distribution
            voting_power = await self._get_voting_power_distribution(protocol_model)
            
            # Calculate cost to gain control
            control_cost = self._calculate_control_cost(voting_power, market_state)
            
            # Estimate value extractable
            extractable_value = await self._estimate_extractable_value(protocol_model)
            
            if extractable_value > control_cost * 1.5:  # 50% profit margin
                opportunities.append(EconomicOpportunity(
                    id="governance_takeover",
                    type=EconomicPrimitive.GOVERNANCE_BUYING,
                    profit_estimate=extractable_value - control_cost,
                    capital_required=control_cost,
                    target_protocol=protocol_model.get('name', 'unknown'),
                    execution_path=[
                        {'action': 'accumulate_tokens'},
                        {'action': 'propose_malicious'},
                        {'action': 'vote'},
                        {'action': 'execute'},
                        {'action': 'extract_value'}
                    ],
                    success_probability=0.6,
                    time_sensitive=False
                ))
        
        return opportunities
    
    async def _get_voting_power_distribution(
        self,
        protocol_model: Dict[str, Any]
    ) -> Dict[str, float]:
        """Get distribution of voting power"""
        # Simplified - would query actual data
        return {
            'whale1': 0.2,
            'whale2': 0.15,
            'whale3': 0.1,
            'others': 0.55
        }
    
    def _calculate_control_cost(
        self,
        voting_power: Dict[str, float],
        market_state: MarketState
    ) -> float:
        """Calculate cost to gain governance control"""
        # Need 51% of voting power
        current_control = max(voting_power.values())
        needed = 0.51 - current_control
        
        if needed > 0:
            # Estimate token price and amount needed
            token_price = 10  # Simplified
            total_supply = 1000000
            tokens_needed = needed * total_supply
            
            return tokens_needed * token_price
        
        return 0
    
    async def _estimate_extractable_value(
        self,
        protocol_model: Dict[str, Any]
    ) -> float:
        """Estimate value that can be extracted through governance"""
        # Check treasury, fees, etc.
        treasury_value = 10000000  # $10M treasury
        
        # Can potentially extract portion of treasury
        return treasury_value * 0.2  # 20% extraction
    
    async def analyze_game_theory(
        self,
        scenario: Dict[str, Any]
    ) -> GameTheoreticScenario:
        """Analyze game theoretic aspects of a scenario"""
        logger.info("Analyzing game theory...")
        
        # Extract players and strategies
        players = scenario.get('players', ['attacker', 'defender'])
        strategies = scenario.get('strategies', {
            'attacker': ['exploit', 'wait'],
            'defender': ['patch', 'ignore']
        })
        
        # Build payoff matrix
        payoff_matrix = self._build_payoff_matrix(players, strategies, scenario)
        
        # Find Nash equilibria
        nash_equilibria = self._find_nash_equilibria(payoff_matrix, strategies)
        
        # Find dominant strategies
        dominant_strategies = self._find_dominant_strategies(payoff_matrix, strategies)
        
        return GameTheoreticScenario(
            players=players,
            strategies=strategies,
            payoff_matrix=payoff_matrix,
            nash_equilibria=nash_equilibria,
            dominant_strategies=dominant_strategies
        )
    
    def _build_payoff_matrix(
        self,
        players: List[str],
        strategies: Dict[str, List[str]],
        scenario: Dict[str, Any]
    ) -> np.ndarray:
        """Build payoff matrix for game"""
        # Simplified 2-player game
        if len(players) == 2:
            p1_strategies = strategies[players[0]]
            p2_strategies = strategies[players[1]]
            
            matrix = np.zeros((len(p1_strategies), len(p2_strategies), 2))
            
            # Fill in payoffs based on scenario
            for i, s1 in enumerate(p1_strategies):
                for j, s2 in enumerate(p2_strategies):
                    payoffs = self._calculate_payoffs(s1, s2, scenario)
                    matrix[i, j] = payoffs
            
            return matrix
        
        return np.array([])
    
    def _calculate_payoffs(
        self,
        strategy1: str,
        strategy2: str,
        scenario: Dict[str, Any]
    ) -> np.ndarray:
        """Calculate payoffs for strategy combination"""
        # Simplified payoff calculation
        if strategy1 == 'exploit' and strategy2 == 'ignore':
            return np.array([1000000, -1000000])  # Attacker wins
        elif strategy1 == 'exploit' and strategy2 == 'patch':
            return np.array([-10000, 10000])  # Defender wins
        elif strategy1 == 'wait' and strategy2 == 'patch':
            return np.array([0, -1000])  # Small cost to defender
        else:
            return np.array([0, 0])  # Status quo
    
    def _find_nash_equilibria(
        self,
        payoff_matrix: np.ndarray,
        strategies: Dict[str, List[str]]
    ) -> List[Tuple[str, ...]]:
        """Find Nash equilibria in game"""
        equilibria = []
        
        # Simplified for 2-player game
        if payoff_matrix.shape[2] == 2:
            players = list(strategies.keys())
            p1_strategies = strategies[players[0]]
            p2_strategies = strategies[players[1]]
            
            for i, s1 in enumerate(p1_strategies):
                for j, s2 in enumerate(p2_strategies):
                    # Check if (s1, s2) is Nash equilibrium
                    if self._is_nash_equilibrium(i, j, payoff_matrix):
                        equilibria.append((s1, s2))
        
        return equilibria
    
    def _is_nash_equilibrium(
        self,
        i: int,
        j: int,
        payoff_matrix: np.ndarray
    ) -> bool:
        """Check if strategy profile is Nash equilibrium"""
        # Player 1 best response
        p1_payoffs = payoff_matrix[:, j, 0]
        if payoff_matrix[i, j, 0] < np.max(p1_payoffs):
            return False
        
        # Player 2 best response
        p2_payoffs = payoff_matrix[i, :, 1]
        if payoff_matrix[i, j, 1] < np.max(p2_payoffs):
            return False
        
        return True
    
    def _find_dominant_strategies(
        self,
        payoff_matrix: np.ndarray,
        strategies: Dict[str, List[str]]
    ) -> Dict[str, Optional[str]]:
        """Find dominant strategies for each player"""
        dominant = {}
        
        players = list(strategies.keys())
        
        # Player 1
        p1_strategies = strategies[players[0]]
        dominant_idx = self._find_dominant_strategy_idx(payoff_matrix[:, :, 0])
        dominant[players[0]] = p1_strategies[dominant_idx] if dominant_idx is not None else None
        
        # Player 2
        if len(players) > 1:
            p2_strategies = strategies[players[1]]
            dominant_idx = self._find_dominant_strategy_idx(payoff_matrix[:, :, 1].T)
            dominant[players[1]] = p2_strategies[dominant_idx] if dominant_idx is not None else None
        
        return dominant
    
    def _find_dominant_strategy_idx(self, payoffs: np.ndarray) -> Optional[int]:
        """Find index of dominant strategy"""
        n_strategies = payoffs.shape[0]
        
        for i in range(n_strategies):
            is_dominant = True
            
            for j in range(n_strategies):
                if i != j:
                    # Check if strategy i dominates strategy j
                    if not np.all(payoffs[i] >= payoffs[j]):
                        is_dominant = False
                        break
            
            if is_dominant:
                return i
        
        return None