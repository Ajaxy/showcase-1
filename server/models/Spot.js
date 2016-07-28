import mongoose, {Schema} from 'mongoose';
import {isEmail} from 'validator';

import config from '../../common/config';

const spotSchema = new Schema({
    lat: {
        type: Number,
        min: -90,
        max: 90,
        required: true,
        index: true
    },
    long: {
        type: Number,
        min: -180,
        max: 180,
        required: true,
        index: true
    },
    bloodGroup: {
        type: Number,
        required: true,
        index: true,
        min: config.BLOOD_GROUP_RANGE.min,
        max: config.BLOOD_GROUP_RANGE.max
    },
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    contactNumber: {
        type: String,
        required: true,
        validate: {
            validator: (v) => /^(00|\+)\d{2} \d{3} \d{4} \d{3}$/.test(v),
            message: '{VALUE} is not a valid phone number!'
        }
    },
    email: {
        type: String,
        required: true,
        validate: {
            validator: (v) => isEmail(v),
            message: '{VALUE} is not a valid Email!'
        }
    },
    updated: {
        type: Date,
        default: Date.now,
        required: true
    }
});

spotSchema.statics.findInBounds = function (bounds, cb) {
    return this
        .where('lat').gte(bounds[0][0]).lte(bounds[1][0])
        .where('long').gte(bounds[0][1]).lte(bounds[1][1])
        .exec(cb);
};

export default mongoose.model('Spot', spotSchema);