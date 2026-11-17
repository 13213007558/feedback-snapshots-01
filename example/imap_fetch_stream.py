import hashlib
from asyncio import run

import aioimaplib


async def fetch_message_streaming(imap_client: aioimaplib.IMAP4_SSL, uid: int) -> bytes:
    """Fetch a message in backpressured chunks instead of buffering the whole literal."""
    stream = imap_client.stream_fetch(str(uid), 'BODY.PEEK[]', by_uid=True,
                                      timeout=30, total_timeout=300, max_queue=8)
    digest = hashlib.sha256()
    size = 0
    try:
        async with stream:
            async for chunk in stream:
                # chunk.command / chunk.tag / chunk.literal_index identify the origin of the bytes
                digest.update(chunk.data)
                size += len(chunk.data)
        await stream.command.wait()  # raises unless the whole literal was received
    except Exception:
        # the transport was already closed: the remaining bytes are never parsed as a new response
        raise
    print('fetched %d bytes sha256=%s' % (size, digest.hexdigest()))
    return digest.digest()


async def imap_loop(host, user, password) -> None:
    imap_client = aioimaplib.IMAP4_SSL(host=host, timeout=30)
    await imap_client.wait_hello_from_server()
    await imap_client.login(user, password)
    await imap_client.select('INBOX')
    await fetch_message_streaming(imap_client, 1)


if __name__ == '__main__':
    run(imap_loop('imap.server', 'account_id', 'password'))
