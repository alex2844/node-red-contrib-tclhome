module.exports = function(RED) {
	function Device(config) {
		RED.nodes.createNode(this, config);
		const settings = RED.nodes.getNode(config.settings);
		this.on('input', msg => {
			const deviceid = RED.util.evaluateNodeProperty(config.deviceid, config.deviceidType, this, msg);
			const params = RED.util.evaluateNodeProperty(config.params, config.paramsType, this, msg);
			const topic = RED.util.evaluateNodeProperty(config.topic, config.topicType, this, msg);
			settings.getClient().then(client => {
				if (params)
					return client.setDevice(deviceid, params);
				else
					return client.getDevice(deviceid);
			})
			.then(payload => {
				msg.topic = topic;
				msg.payload = payload;
				this.send(msg);
			})
			.catch(({ message, code }) => {
				msg.code = code;
				msg.payload = message;
				this.error(message, msg);
			});
		});
	};
	RED.nodes.registerType('device', Device);
}
