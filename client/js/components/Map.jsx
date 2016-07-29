import React from 'react';
import ReactDOM from 'react-dom';
import {forEach, values} from 'underscore';

import config from '../../../common/config';
import BecomeDonor from './BecomeDonor';
import SpotForm from './SpotForm';
import setupMap from '../tools/setupMap';
import styles from '../../styles/components/Map.less';

export default class Map extends React.Component {
    componentDidMount () {
        this.map = setupMap({
            container: 'map-view',
            center: config.INITIAL_MAP_CENTER,
            zoom: config.INITIAL_MAP_ZOOM,
            onBoundsChange: this.props.handleBoundsChange,
            onPopupOpen: this.props.openPopup
        });
    }

    componentDidUpdate () {
        if (!this.map) {
            return;
        }

        this.setupSpots(this.props.spots);

        if (this.props.mode == config.MODE_DONOR) {
            const spot = this.props.spot;

            if (!this.spotForm) {
                this.spotForm = ReactDOM.findDOMNode(this.refs.spotForm);
            }

            this.map.setupPopupOnClick(this.spotForm);

            if (spot && spot._id != this.removedSpot) {
                this.map.openPopup({
                    coords: [spot.long, spot.lat],
                    content: this.spotForm,
                    url: `/donor/${spot._id}`
                });
            }
        } else {
            this.map.cancelPopupOnClick();
        }
    }

    setupSpots (spots) {
        if (!spots) {
            return;
        }
        
        if (!this.currentSpots) {
            this.currentSpots = {};
        }

        let changed = false;

        // Check for removed.
        forEach(this.currentSpots, (spot, id) => {
            if (!(id in spots)) {
                delete this.currentSpots[id];

                if (!changed) {
                    changed = true;
                }
            }
        });

        // Check for new and updated.
        forEach(spots, (spot, id) => {
            if (!(id in this.currentSpots) || spot.updated > this.currentSpots[id].updated) {
                this.currentSpots[id] = spot;

                if (!changed) {
                    changed = true;
                }
            }
        });

        if (changed) {
            this.map.setupSpots(values(this.currentSpots));
        }
    }

    handleRemoveSpot () {
        this.removedSpot = this.props.spot._id;
        this.map.closePopup();
    }

    render () {
        const classNames = [styles['map-container']];
        
        if (this.props.spot) {
            classNames.push(styles['disable-balloon-close']);
        }
        
        return (
            <div className={classNames.join(' ')}>
                <div id="map-view" className={styles['map-view']}></div>
                <BecomeDonor {...this.props} />
                <SpotForm ref="spotForm" {...this.props} onRemoveSpot={this.handleRemoveSpot.bind(this)} />
            </div>
        );
    }
}