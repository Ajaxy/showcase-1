export default (point, bounds) => {
    return bounds[0][0] <= point[0] && bounds[0][1] <= point[1] &&
        point[0] <= bounds[1][0] && point[1] <= bounds[1][1];
};