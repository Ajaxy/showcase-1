import chai from 'chai';
import chaiImmutable from 'chai-immutable'
import mongoose from 'mongoose';

chai.use(chaiImmutable);

mongoose.Promise = Promise;
// mongoose.set('debug', true);