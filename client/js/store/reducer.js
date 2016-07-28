import {fromJS} from 'immutable';

import config from '../../../common/config';

function setFromJs (state, key, value) {
    return state.set(key, fromJS(value));
}

export default (state = fromJS({}), action) => {
    switch (action.type) {
        case 'CHANGE_BOUNDS':
            return setFromJs(state, 'bounds', action.bounds);

        case 'LOAD_SPOTS':
            return setFromJs(state, 'spots', action.spots);

        case 'SET_MODE':
            return setFromJs(state, 'mode', action.mode);

        case 'OPEN_POPUP':
            return setFromJs(state, 'popupCoords', action.coords);

        case 'SAVE_SPOT':
            return setFromJs(state, 'spot', action.spot);

        case 'UPDATE_SPOT':
            return setFromJs(state, 'spot', action.spot);

        case 'LOAD_SPOT':
            return state.merge({
                mode: config.MODE_DONOR,
                spot: action.spot
            });
    }

    return state;
}
