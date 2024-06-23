module.exports = async function(RED) {
	const { TCLHome } = await import('../index.mjs');
	function Config(config) {
		RED.nodes.createNode(this, config);
		console.log('credentials', this.credentials);
		this.getClient = async function() {
			const client = new TCLHome(this.credentials);
			// TMP
			client.on('auth', credentials => console.log('auth', JSON.stringify(credentials)));
			client.on('refreshToken', credentials => console.log('refreshToken', JSON.stringify(credentials)));
			client.on('cognitoToken', credentials => console.log('cognitoToken', JSON.stringify(credentials)));
			// TMP
			/*
			client.on('auth', credentials => RED.nodes.addCredentials(this.id, credentials));
			client.on('refreshToken', credentials => RED.nodes.addCredentials(this.id, credentials));
			client.on('cognitoToken', credentials => RED.nodes.addCredentials(this.id, credentials));
			*/
			return client;
		};
	};
	RED.nodes.registerType('config', Config, {
		credentials: {
			username: { type: 'text' },
			password: { type: 'password' },
			country: { type: 'text' }
		}
	});
}
