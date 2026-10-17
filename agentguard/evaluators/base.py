"""Base evaluator interface."""

from abc import ABC, abstractmethod

from agentguard.models import AgentTrace, Finding


class BaseEvaluator(ABC):
    """Abstract base class for all deterministic trace evaluators."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for the evaluation rule."""

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Human-readable name of the evaluation rule."""

    @abstractmethod
    def evaluate(self, trace: AgentTrace) -> list[Finding]:
        """Evaluates an agent trace and returns any security or quality findings."""
