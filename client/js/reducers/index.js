import {fromJS, Map} from 'immutable';

import {
    SET_MODE, OPEN_POPUP, CHANGE_BOUNDS,
    LOAD_SPOTS, CREATE_IN_SPOTS, UPDATE_IN_SPOTS, REMOVE_FROM_SPOTS,
    LOAD_SPOT, SAVE_SPOT, REMOVE_SPOT
} from '../actions';

function setFromJs (state, key, value) {
    return state.set(key, fromJS(value));
}

function indexBy (iterable, key) {
    return iterable.reduce(
        (lookup, item) => lookup.set(item.get(key), item),
        Map()
    );
}

export default (state = Map(), action) => {
    switch (action.type) {
        case SET_MODE:
            return setFromJs(state, 'mode', action.mode);

        case OPEN_POPUP:
            if (state.get('spot')) {
                state = state.updateIn(['spot'], (spot) => spot.merge({
                    lat: action.coords.latitude,
                    long: action.coords.longitude
                }))
            }

            return setFromJs(state, 'popupCoords', action.coords);
        
        case CHANGE_BOUNDS:
            return setFromJs(state, 'bounds', action.bounds);

        case LOAD_SPOTS:
            const newSpots = indexBy(fromJS(action.spots), '_id');
            return state.updateIn(['spots'], Map(), (spots) => spots.merge(newSpots));

        case CREATE_IN_SPOTS:
            return state.setIn(['spots', action.id], Map(action.spot));

        case UPDATE_IN_SPOTS:
            return state.updateIn(['spots', action.id], (spot) => spot.merge(action.spot));

        case REMOVE_FROM_SPOTS:
            return state.removeIn(['spots', action.id]);

        case SAVE_SPOT:
            return setFromJs(state, 'spot', action.spot);

        case REMOVE_SPOT:
            return state.remove('spot');

        case LOAD_SPOT:
            return setFromJs(state, 'spot', action.spot);
    }

    return state;
}
