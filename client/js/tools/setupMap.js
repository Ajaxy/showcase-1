export default ({ container, center, zoom, onBoundsChange, onPopupOpen }) => {
    let popupContent;
    let view;
    const ready = new Promise((resolve) => {
        __non_webpack_require__([
            'esri/Map',
            'esri/views/MapView',
            'esri/PopupTemplate',
            'esri/geometry/Point',
            'esri/geometry/ScreenPoint',
            'esri/geometry/SpatialReference',
            'esri/geometry/support/webMercatorUtils',
            'esri/symbols/PictureMarkerSymbol',
            'esri/layers/FeatureLayer',
            'esri/layers/support/Field',
            'esri/widgets/Search',
            'esri/widgets/Locate'
        ], (
            Map, MapView, PopupTemplate, Point, ScreenPoint, SpatialReference, webMercatorUtils,
            PictureMarkerSymbol, FeatureLayer, Field, Search, Locate
        ) => {
            const map = new Map({
                basemap: 'streets-vector'
            });

            view = new MapView({
                container: container,
                map: map,
                zoom: zoom,
                center: center
            });

            const searchWidget = new Search({ view: view, popupEnabled: false });
            searchWidget.startup();
            view.ui.add(searchWidget, {
                position: 'top-left',
                index: 0
            });

            const locateWidget = new Locate({ view: view });
            locateWidget.startup();
            view.ui.add(locateWidget, {
                position: 'top-left',
                index: 1
            });

            const featureLayer = new FeatureLayer({
                source: [],
                fields: [new Field({
                    name: '_id',
                    type: 'oid'
                }), new Field({
                    name: 'firstName',
                    type: 'string'
                }), new Field ({
                    name: 'lastName',
                    type: 'string'
                }), new Field({
                    name: 'contactNumber',
                    type: 'string'
                }), new Field ({
                    name: 'email',
                    type: 'string'
                }), new Field ({
                    name: 'bloodGroup',
                    type: 'number'
                })],
                objectIdField: '_id',
                geometryType: 'point',
                spatialReference: SpatialReference.WebMercator,
                popupTemplate: new PopupTemplate({
                    title: '{firstName} {lastName}',
                    content: `<ul>
                        <li>Blood group: {bloodGroup}</li>
                        <li>Contact number: <span class="masked" onclick="this.className = '';">{contactNumber}</span></li>
                        <li>E-mail: <span class="masked" onclick="this.className = '';">{email}</span></li>
                    </ul>`
                })
            });

            map.add(featureLayer);

            view.openPopup = (coords, content, url) => {
                const [longitude, latitude] = coords;

                view.popup.open({
                    title: url ? `<a href="${url}" class="url">URL: ${url}</a>` : 'Please, fill the form',
                    location: new Point({ longitude, latitude, spatialReference: SpatialReference.WebMercator }),
                    content
                });
            };

            view.addSpot = (spot) => {
                featureLayer.source.push({
                    geometry: new Point({
                        longitude: spot.long,
                        latitude: spot.lat,
                        spatialReference: SpatialReference.WebMercator
                    }),
                    symbol: new PictureMarkerSymbol({
                        width: '16px',
                        height: '16px',
                        url: '/img/icon.png'
                    }),
                    attributes: spot
                });
            };

            view.watch('extent', (extent) => {
                onBoundsChange([
                    webMercatorUtils.xyToLngLat(extent.xmin, extent.ymin).reverse(),
                    webMercatorUtils.xyToLngLat(extent.xmax, extent.ymax).reverse()
                ]);
            });

            view.on('click', (e) => {
                if (popupContent) {
                    const [longitude, latitude] = [e.mapPoint.longitude, e.mapPoint.latitude];
                    view.openPopup([longitude, latitude], popupContent);
                    onPopupOpen({ longitude, latitude });
                }
            });

            resolve();
        });
    });

    return {
        addSpot: (spot) => {
            ready.then(() => {
                view.addSpot(spot);
            });
        },

        setupPopupOnClick: (content) => {
            popupContent = content;
        },

        cancelPopupOnClick: () => {
            popupContent = null;
        },

        openPopup: ({ coords, content, url }) => {
            ready.then(() => {
                view.openPopup(coords, content, url);
            });
        }
    };
};