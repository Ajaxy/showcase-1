import React from 'react';
import ReactDOM from 'react-dom';
import {createStore, applyMiddleware} from 'redux';
import {Provider} from 'react-redux';
import thunk from 'redux-thunk'
import {fromJS} from 'immutable';

import * as actions from './store/actions';
import reducer from './store/reducer';
import socket from './tools/socket';
import {AppContainer} from './components/App';

import styles from '../styles/global.less';

const store = createStore(reducer, fromJS({}), applyMiddleware(thunk));
store.dispatch(actions.loadSpot());

socket
    .on('spotcreate', (data) => store.dispatch(actions.createInSpots(data.id, data.spot)))
    .on('spotupdate', (data) => store.dispatch(actions.updateInSpots(data.id, data.spot)))
    .on('spotremove', (data) => store.dispatch(actions.removeFromSpots(data.id)));

ReactDOM.render(
    <Provider store={store}>
        <AppContainer />
    </Provider>,
    document.getElementById('app')
);
