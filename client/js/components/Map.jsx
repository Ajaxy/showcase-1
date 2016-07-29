import React from 'react';
import ReactDOM from 'react-dom';

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

        this.addSpots(this.props.spots);
        
        if (this.props.mode == config.MODE_DONOR) {
            const spot = this.props.spot;
        
            if (!this.spotForm) {
                this.spotForm = ReactDOM.findDOMNode(this.refs.spotForm);
            }
        
            if (spot) {
                this.map.cancelPopupOnClick();
                this.map.openPopup({
                    coords: [spot.long, spot.lat],
                    content: this.spotForm,
                    url: `/donor/${spot._id}`
                });
            } else {
                this.map.setupPopupOnClick(this.spotForm);
            }
        } else {
            this.map.cancelPopupOnClick();
        }
    }

    addSpots (spots) {
        if (!spots) {
            return;
        }
        
        if (!this.addedSpotIds) {
            this.addedSpotIds = {};
        }

        spots.forEach((spot) => {
            if (!(spot._id in this.addedSpotIds)) {
                this.addedSpotIds[spot._id] = true;
                this.map.addSpot(spot);
            }
        });
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
                <SpotForm ref="spotForm" {...this.props} />
            </div>
        );
    }
}