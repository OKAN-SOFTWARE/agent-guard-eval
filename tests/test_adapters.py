"""Tests for LangChain / LangGraph adapter and LangSmith parser."""

from agentguard.adapters.langchain import AgentGuardCallbackHandler, parse_langsmith_run


def test_callback_handler_trace_lifecycle():
    handler = AgentGuardCallbackHandler(session_id="test-lc-1", agent_name="qa_agent")

    # 1. Chain start
    handler.on_chain_start(
        serialized=None, inputs={"input": "What is the capital of France?"}
    )

    # 2. Tool start and end
    handler.on_tool_start(serialized={"name": "search"}, input_str="capital of France")
    handler.on_tool_end(output="Paris")

    # 3. Chain end
    handler.on_chain_end(outputs={"output": "The capital of France is Paris."})

    trace = handler.get_trace()
    assert trace.session_id == "test-lc-1"
    assert trace.user_prompt == "What is the capital of France?"
    assert trace.final_response == "The capital of France is Paris."
    assert len(trace.tool_calls) == 1
    assert trace.tool_calls[0].tool_name == "search"
    assert trace.tool_calls[0].output == "Paris"
    assert trace.tool_calls[0].duration_ms is not None

    # Evaluate directly from handler
    eval_result = handler.evaluate()
    assert eval_result.passed


def test_callback_handler_tool_error():
    handler = AgentGuardCallbackHandler(session_id="test-lc-err")
    handler.on_tool_start(serialized={"name": "bash"}, input_str="rm -rf /")
    handler.on_tool_error(error=RuntimeError("Permission denied"))

    trace = handler.get_trace()
    assert len(trace.tool_calls) == 1
    assert trace.tool_calls[0].error == "Permission denied"

    result = handler.evaluate()
    # Should be flagged by SecurityGuard for rm -rf
    assert not result.passed


def test_parse_langsmith_run():
    run_dict = {
        "id": "run-xyz-123",
        "name": "langsmith_agent",
        "inputs": {"input": "Check server uptime"},
        "outputs": {"output": "Uptime is 99.99%"},
        "child_runs": [
            {
                "name": "check_status",
                "run_type": "tool",
                "inputs": {"host": "internal.service"},
                "outputs": {"output": "UP"},
                "start_time": 1000.0,
                "end_time": 1050.0,
            }
        ],
    }

    trace = parse_langsmith_run(run_dict)
    assert trace.session_id == "run-xyz-123"
    assert trace.user_prompt == "Check server uptime"
    assert len(trace.tool_calls) == 1
    assert trace.tool_calls[0].tool_name == "check_status"
    assert trace.tool_calls[0].output == "UP"
