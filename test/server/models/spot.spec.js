import {expect} from 'chai';
import {fromJS} from 'Immutable';

import * as helpers from '../../helpers';
import Spot from '../../../server/models/Spot';

const mock = fromJS({
    lat: 55.7558,
    long: 37.6173,
    firstName: 'John',
    lastName: 'Doe',
    contactNumber: '+18 777 6092 233',
    email: 'john@doe.com',
    bloodGroup: 2,
    ip: '127.0.0.1'
});

describe('Spot', () => {
    before(helpers.dbConnect);
    after(helpers.dbDisconnect);

    afterEach(() => Spot.remove({}));
    
    it('should be created', () => {
        const spot = new Spot(mock.toJS());

        return spot.save()
            .then(() => Spot.find({}))
            .then((spots) => {
                expect(spots.length).to.equal(1);
                expect(spots[0].firstName).to.equal(mock.get('firstName'));
            });
    });

    it('can be found within bounds', () => {
        return Spot.create([
            mock.merge({ lat: -90, long: -180 }).toJS(),
            mock.toJS(),
            mock.merge({ lat: 56, long: 38 }).toJS(),
            mock.merge({ lat: 56, long: 39 }).toJS()
        ])
            .then(() => Spot.findInBounds([[-89, -180], [56, 38]]))
            .then((spots) => {
                expect(spots.length).to.equal(2)
            });
    });

    describe('validations', () => {
        it('should require needed fields', () => {
            const required = mock.keySeq().toJS().sort();
            const spot = new Spot({});

            return spot.save()
                .then(() => Promise.reject('unexpected resolve'))
                .catch((err) => {
                    expect(err).to.have.property('errors');
                    expect(required).to.eql(Object.keys(err.errors).sort());
                });
        });

        it('should validate latitude', () => checkFieldValidation('lat', 90.5));

        it('should validate longitude', () => checkFieldValidation('long', -180.5));

        it('should validate email', () => checkFieldValidation('email', 'wrong'));

        it('should validate contact number', () => checkFieldValidation('contactNumber', 'wrong'));

        it('should validate blood group', () => checkFieldValidation('bloodGroup', 5));
    });
});

function checkFieldValidation (field, wrongValue) {
    const spot = new Spot(mock.set(field, wrongValue).toJS());

    return spot.save()
        .then(() => Promise.reject('unexpected resolve'))
        .catch((err) => {
            expect(err).to.have.property('errors');
            expect(Object.keys(err.errors)).to.eql([field]);
        });
}