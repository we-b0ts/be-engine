"""Synthetic Python Socket.IO Source; disconnect work outlives WS close echo."""
import asyncio

import socketio
import uvicorn


async def main():
    sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
    socket_app = socketio.ASGIApp(sio)
    turn = 0

    @sio.event
    async def ask(sid, value):
        return value

    @sio.event
    async def disconnect(sid, reason):
        nonlocal turn
        turn += 1
        current = turn
        # This begins beyond the normal 100 ms post-response window, after
        # Uvicorn has already echoed a transport-level CLOSE to its peer.
        await asyncio.sleep(0.18)
        reader, writer = await asyncio.open_connection('redis.close.test', 6379)
        key = f'late-{current}'.encode()
        writer.write(b'*2\r\n$3\r\nGET\r\n$' + str(len(key)).encode() + b'\r\n' + key + b'\r\n')
        await writer.drain()
        assert await reader.readexactly(8) == b'$2\r\nok\r\n'
        writer.close()
        await writer.wait_closed()
        print(f'application disconnect completed: {current}', flush=True)

    async def dependency(reader, writer):
        assert await reader.readline() == b'*2\r\n'
        assert await reader.readline() == b'$3\r\n'
        assert await reader.readline() == b'GET\r\n'
        length = int((await reader.readline())[1:])
        assert (await reader.readexactly(length + 2)).startswith(b'late-')
        await asyncio.sleep(0.14)
        writer.write(b'$2\r\nok\r\n')
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def app(scope, receive, send):
        if scope['type'] == 'http' and scope['path'] == '/health':
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'{}'})
        else:
            await socket_app(scope, receive, send)

    redis = await asyncio.start_server(dependency, '127.0.0.1', 6379)
    async with redis:
        server = uvicorn.Server(uvicorn.Config(
            app, host='127.0.0.1', port=8080, ws='websockets-sansio',
            lifespan='off', log_level='warning', access_log=False,
        ))
        await server.serve()


if __name__ == '__main__':
    asyncio.run(main())
