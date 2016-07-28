import S from 'string';

import * as spotsController from '../controllers/spots';

// May be enhanced with async module loader to use with multiple controllers.
const controllers = {
    spots: spotsController
};

export default function setupSocketRouter (socket) {
    socket.on('request', onRequest);
}

function onRequest (data, cb) {
    const promise = route(data.url, data.params);

    if (cb) {
        promise
            .then(cb)
            .catch((err) => cb({ error: err.message||err }));
    }
}

function route (url, params = {}, source) {
    return new Promise((resolve, reject) => {
        // MATCH /:controller/:action
        const match = url.match(/^\/([\w\_]+)(\/([\w\_]+))/i);

        if (!match || match.length != 4) {
            reject('Wrong URL');
            return;
        }

        const controller = S(match[1]).camelize().toString();
        const controllerActions = controllers[controller];
        if (!controllerActions) {
            reject('Wrong controller');
            return;
        }
        
        const action = S(match[3]).camelize().toString();
        if (typeof controllerActions[action] != 'function') {
            reject('Wrong action');
        }

        Object.assign(params, { controller, action });

        resolve(controllerActions[action](params));
    });
}