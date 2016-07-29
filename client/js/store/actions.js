import config from '../../../common/config';
import socket from '../tools/socket';
import isInBounds from '../tools/isInBounds';

export function changeBounds (bounds) {
    return { type: 'CHANGE_BOUNDS', bounds };
}

export function loadSpots (bounds) {
    return (dispatch) => {
        socket.request('/spots/find_in_bounds', { bounds }).then((spots) => {
            dispatch({ type: 'LOAD_SPOTS', spots });
        }).catch();
    }
}

export function handleBoundsChange (bounds) {
    return (dispatch) => {
        dispatch(changeBounds(bounds));

        if (true/* Check if already loaded */) {
            dispatch(loadSpots(bounds));
        }
    }
}

export function createInSpots (id, spot) {
    return (dispatch, getState) => {
        if (isInBounds([spot.lat, spot.long], getState().get('bounds').toJS())) {
            dispatch({ type: 'CREATE_IN_SPOTS', id, spot });
        }
    };
}

export function updateInSpots (id, spot) {
    return { type: 'UPDATE_IN_SPOTS', id, spot };
}

export function removeFromSpots (id) {
    return { type: 'REMOVE_FROM_SPOTS', id };
}

export function setMode (mode) {
    return { type: 'SET_MODE', mode };
}

export function openPopup (coords) {
    return (dispatch) => {
        dispatch({ type: 'OPEN_POPUP', coords });
        dispatch(updateSpot());
    };
}

export function loadSpot () {
    return (dispatch) => {
        const match = location.pathname.match(/donor\/(.*)+/);

        if (match && match[1]) {
            socket.request('/spots/find_by_id', { id: match[1] }).then((spot) => {
                dispatch(setMode(config.MODE_DONOR));
                dispatch({ type: 'LOAD_SPOT', spot });
            });
        }
    }
}

export function createSpot (spot) {
    return (dispatch, getState) => {
        const coords = getState().get('popupCoords').toJS();
        spot.lat = coords.latitude;
        spot.long = coords.longitude;

        socket.request('/spots/create', { spot }).then((spot) => {
            history.replaceState({}, null, '/donor/' + spot._id);
            dispatch({ type: 'SAVE_SPOT', spot });
        }).catch(alert);
    };
}

export function updateSpot (params) {
    return (dispatch, getState) => {
        const coords = getState().get('popupCoords').toJS();
        let spot = getState().get('spot');

        if (!spot) {
            return;
        }

        spot = spot.merge(params).merge({
            lat: coords.latitude,
            long: coords.longitude
        }).toJS();
        
        socket.request('/spots/update', { spot }).then((spot) => {
            dispatch({ type: 'SAVE_SPOT', spot });
        }).catch(alert);
    };
}

export function removeSpot () {
    return (dispatch, getState) => {
        const id = getState().get('spot').get('_id');

        socket.request('/spots/remove', { id }).then((params) => {
            dispatch({ type: 'REMOVE_SPOT', id: params.id });
            dispatch(setMode(config.MODE_PATIENT));
        }).catch(alert);
    };
}
