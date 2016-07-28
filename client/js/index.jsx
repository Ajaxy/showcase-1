import React from 'react';
import ReactDOM from 'react-dom';
import {createStore, applyMiddleware} from 'redux';
import {Provider} from 'react-redux';
import thunk from 'redux-thunk'
import {fromJS} from 'immutable';

import * as actions from './store/actions';
import reducer from './store/reducer';
import {AppContainer} from './components/App';

import styles from '../styles/global.less';

const store = createStore(reducer, fromJS({}), applyMiddleware(thunk));

store.dispatch(actions.loadSpot());

ReactDOM.render(
    <Provider store={store}>
        <AppContainer />
    </Provider>,
    document.getElementById('app')
);
