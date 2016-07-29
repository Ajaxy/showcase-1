import {expect} from 'chai';

import isInBounds from '../../../client/js/tools/isInBounds';

describe('isInBounds', () => {
    it('should return `true` if contains point', () => {
        expect(isInBounds(
            [0, 0],
            [[-90, -180], [90, 180]]
        )).to.be.true;

        expect(isInBounds(
            [0, 0],
            [[0, 0], [1, 1]]
        )).to.be.true;
    });

    it('should return `false` if not contains point', () => {
        expect(isInBounds(
            [-90, 0],
            [[0, -180], [90, 180]]
        )).to.be.false;

        expect(isInBounds(
            [0, 180],
            [[-90, -180], [90, 0]]
        )).to.be.false;
    });
});