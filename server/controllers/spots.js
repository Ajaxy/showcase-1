import Spot from '../models/Spot';

export function findById (params) {
    return Spot.findById(params.id)
        .catch(() => Promise.reject('Wrong id'));
}

export function findInBounds (params) {
    return Spot.findInBounds(params.bounds).then((spots) => {
        return spots && spots.length ? spots : Promise.reject('Nothing found');
    });
}

export function create (params) {
    return Spot.create(params.spot);
}

export function update (params) {
    return Spot.findById(params.spot._id).then((spot) => {
        // Whitelist filter for params needed.
        Object.assign(spot, params.spot);

        return spot.save();
    });
}