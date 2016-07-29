import io from '../tools/io';
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
    return Spot.create(params.spot)
        .then((spot) => {
            io.emit('spotcreate', { spot: spot, id: spot.id });
            
            return spot;
        });
}

export function update (params) {
    return Spot.findById(params.spot._id).then((spot) => {
        // Whitelist filter for params needed.
        Object.assign(spot, params.spot, { updated: Date.now() });

        return spot.save();
    }).then((spot) => {
        io.emit('spotupdate', { spot: spot, id: spot.id });
        
        return spot;
    }).catch(console.log.bind(console));
}

export function remove (params) {
    return Spot.findOneAndRemove({ _id: params.id })
        .then((spot) => {
            io.emit('spotremove', { id: spot.id });

            return { id: spot.id };
        });
}