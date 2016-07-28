import socket from '../tools/socket'

export function changeBounds (bounds) {
    return { type: 'CHANGE_BOUNDS', bounds };
}

export function loadSpots (bounds) {
    return (dispatch) => {
        socket.request('/spots/find_in_bounds', { bounds }).then((spots) => {
            dispatch({ type: 'LOAD_SPOTS', spots });
        });
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

export function setMode (mode) {
    return { type: 'SET_MODE', mode };
}

export function openPopup (coords) {
    return { type: 'OPEN_POPUP', coords };
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

export function updateSpot (spot) {
    return (dispatch, getState) => {
        socket.request('/spots/update', {
            spot: getState().get('spot').merge(spot).toJS()
        }).then((spot) => {
            dispatch({ type: 'SAVE_SPOT', spot });
        }).catch(alert);
    };
}

export function loadSpot () {
    return (dispatch) => {
        const match = location.pathname.match(/donor\/(.*)+/);

        if (match && match[1]) {
            socket.request('/spots/find_by_id', { id: match[1] }).then((spot) => {
                dispatch({ type: 'LOAD_SPOT', spot });
            });
        }
    }
}
