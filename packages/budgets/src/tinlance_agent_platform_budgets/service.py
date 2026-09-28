from dataclasses import replace
from tinlance_agent_platform_contracts import Budget
class BudgetService:
    def __init__(self,budget:Budget)->None:self._budget=budget
    @property
    def budget(self)->Budget:return self._budget
    def consume_turn(self,elapsed_seconds:float)->None:
        if elapsed_seconds<0: raise ValueError("elapsed time cannot be negative")
        if self._budget.consumed_turns+1>self._budget.max_turns: raise TimeoutError("maximum turns exceeded")
        if self._budget.elapsed_seconds+elapsed_seconds>self._budget.max_seconds: raise TimeoutError("maximum runtime exceeded")
        self._budget=replace(self._budget,consumed_turns=self._budget.consumed_turns+1,elapsed_seconds=self._budget.elapsed_seconds+elapsed_seconds)
    def consume_tool_call(self)->None:
        if self._budget.consumed_tool_calls+1>self._budget.max_tool_calls: raise TimeoutError("maximum tool calls exceeded")
        self._budget=replace(self._budget,consumed_tool_calls=self._budget.consumed_tool_calls+1)
