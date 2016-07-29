import {createStore, applyMiddleware} from 'redux';
import thunk from 'redux-thunk'
import {fromJS} from 'immutable';

import reducer from '../reducers';

export default () => {
    return createStore(reducer, fromJS({}), applyMiddleware(thunk));
}