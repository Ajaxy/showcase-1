import io from 'socket.io-client';

const socket = io(`${location.protocol}//${location.hostname}:8090`);

socket.request = (url, params) => {
    return new Promise((resolve, reject) => {
        socket.emit('request', { url, params }, (res) => {
            if (res && res.error) {
                reject(res.error);
            } else {
                resolve(res);
            }
        });

        setTimeout(() => reject('Socket request timeout'), 3000);
    });
};

export default socket;