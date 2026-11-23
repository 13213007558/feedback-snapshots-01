# Local development setup

Python 3.12

Run from the repository root:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'from anyio import run, create_memory_object_stream, move_on_after; exec("async def main():\n    send, receive = create_memory_object_stream(1)\n    with move_on_after(1) as scope:\n        async with send, receive:\n            await send.send(\"fixture\")\n            assert await receive.receive() == \"fixture\"\n    assert not scope.cancel_called"); run(main); print("Local stream transfer and cancellation scope passed")'
```
