import mongoose from 'mongoose';
import mockgoose from 'mockgoose';

export function dbConnect () {
    return mockgoose(mongoose).then(() => {
        return new Promise((resolve, reject) => {
            mongoose.connect('mongodb://localhost:27017/test', (err) => {
                err ? reject(err) : resolve();
            });
        });
    });
}

export function dbDisconnect (done) {
    mongoose.unmock(() => done());
}