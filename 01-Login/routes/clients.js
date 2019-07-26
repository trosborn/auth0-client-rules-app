const express = require('express');
const secured = require('../lib/middleware/secured');
const router = express.Router();
const ManagementClient = require('auth0').ManagementClient;
const auth0 = new ManagementClient({
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.NON_INTERACTIVE_CLIENT_ID,
  clientSecret: process.env.NON_INTERACTIVE_CLIENT_SECRET,
});

router.get('/clients', secured(), function (req, res, next) {
  Promise.all([ auth0.getRules(), auth0.getClients() ]).then(values => {
    const rules = values[0];
    const clientIDs = values[1].map(e => {
      return e.client_id;
    });

    // Create an object containing each client_id as a key
    const clientRules = {};
    clientIDs.forEach(id => {
      clientRules[id] = [];
    });

    rules.forEach(rule => {
      // Search and extract whitelist from comment
      const whitelistStartPosition = rule.script.search('WHITELIST:');
      const whitelistEndPosition = rule.script.search(':END');
      const whitelistString = rule.script.substring(whitelistStartPosition, whitelistEndPosition).replace('WHITELIST:', '');
      // If whiteListEndPosition is -1, it means no whitelist was found.
      // Therefore, the rule runs on all apps
      if (whitelistString.length === 0) {
        // Add rule to all apps
        Object.keys(clientRules).forEach(key => {
          clientRules[key].push(`${rule.name}`);
        });
      } else {
        // Otherwise, add it only to apps found in the WHITELIST
        const whitelistedClients = whitelistString.split(',')
        whitelistedClients.forEach(id => {
          Object.keys(clientRules).forEach(key => {
            if (id === key) {
              clientRules[key].push(`${rule.name}`);
            }
          });
        });
      }
    });

    res.render('client', {
      clientRules: clientRules
    });
  });
});

module.exports = router;
