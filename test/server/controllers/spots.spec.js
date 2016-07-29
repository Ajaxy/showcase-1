import {expect} from 'chai';
import {fromJS} from 'immutable';

import * as helpers from '../../helpers';
import * as controller from '../../../server/controllers/spots';
import Spot from '../../../server/models/Spot';

const mock = fromJS({
    url: 'something',
    lat: 55.7558,
    long: 37.6173,
    firstName: 'John',
    lastName: 'Doe',
    contactNumber: '+18 777 6092 233',
    email: 'john@doe.com',
    bloodGroup: 2,
    ip: '127.0.0.1'
});

describe('spotController', () => {
    before(helpers.dbConnect);
    after(helpers.dbDisconnect);

    afterEach(() => Spot.remove({}));
    
    it('should create Spot', () => {
        return controller.create({ spot: mock.toJS() }, { conn: { remoteAddress: 'Test IP' } })
            .then(() => Spot.find({}))
            .then((spots) => {
                expect(spots.length).to.equal(1);
                expect(spots[0].firstName).to.equal(mock.get('firstName'));
                expect(spots[0].ip).to.equal('Test IP');
            });
    });

    it('should update Spot', () => {
        let created;

        return Spot.create(mock.toJS())
            .then((spot) => {
                created = spot.updated;
                return spot;
            })
            .then((spot) => controller.update(
                { spot: Object.assign(spot, { firstName: 'New name' }) },
                { conn: { remoteAddress: 'New IP' } }
            ))
            .then(() => Spot.find({}))
            .then((spots) => {
                expect(spots.length).to.equal(1);
                expect(spots[0].firstName).to.equal('New name');
                expect(spots[0].ip).to.equal('New IP');
                expect(spots[0].updated).to.be.gt(created);
            });
    });

    it('should remove Spot', () => {
        return Spot.create(mock.toJS())
            .then((spot) => controller.remove({ id: spot._id }))
            .then((result) => {
                expect(result.id).to.be.a('string');
            })
            .then(() => Spot.find({}))
            .then((spots) => {
                expect(spots.length).to.equal(0);
            });
    });
    
    it('should find Spot by ID', () => {
        return Spot.create(mock.toJS())
            .then((spot) => controller.findById({ id: spot.id }))
            .then((spot) => {
                expect(spot.firstName).to.equal(mock.get('firstName'));
            });
    });
    
    it('should reject promise if no Spot found by ID', () => {
        return controller.findById({ id: 'nothing' })
            .then(() => Promise.reject('unexpected resolve'))
            .catch((err) => {
                expect(err).to.equal('Wrong id');
            });
    });

    it('should find Spots within bounds', () => {
        return Spot.create([
            mock.merge({ lat: -90, long: -180, url: Math.random() }).toJS(),
            mock.toJS(),
            mock.merge({ lat: 56, long: 38, url: Math.random() }).toJS(),
            mock.merge({ lat: 56, long: 39, url: Math.random() }).toJS()
        ])
            .then(() => controller.findInBounds({ bounds: [[-89, -180], [56, 38]] }))
            .then((spots) => {
                expect(spots.length).to.equal(2)
            });
    });

    it('should reject promise if no Spots found in bounds', () => {
        return Spot.create([
            mock.merge({ lat: -90, long: -180, url: Math.random() }).toJS(),
            mock.toJS(),
            mock.merge({ lat: 56, long: 38, url: Math.random() }).toJS(),
            mock.merge({ lat: 56, long: 39, url: Math.random() }).toJS()
        ])
            .then(() => controller.findInBounds({ bounds: [[60, 40], [61, 41]] }))
            .then(() => Promise.reject('unexpected resolve'))
            .catch((err) => {
                expect(err).to.equal('Nothing found');
            });
    });
});