# directus-extension-endpoint-gamecenter-signup
Allows an Apple GameCenter app to post the data from Gamecenter's `fetchItemsForIdentityVerificationSignature()` function to create a user in Directus and returns OAuth2 tokens for it. This is a directus.io endpoint extension that will allow you to create a backend user that can call APIs in Directus from automatic signin provided by GameCentre.

# Setup
1. You need an Apple platform app that has the GameCentre entitlement turned on
2. Setup the gamecentre login following standard Apple documentation, and then on successful login,
3. issue a call to fetchItemsForIdentityVerificationSignature() on GKLocalPlayer
4. Send the data as shown below to your Directus server which has this repository's extension installed and it will verify the login and return token information for further use.

# Sample Swift code
```Swift
GKLocalPlayer.local.authenticateHandler = { [self] viewController, error in
    if let viewController = viewController {
        logger.log("Showing iOS GC ViewController: \(viewController)...")
        show(viewController, sender: self)
        return
    }
    if error != nil {
        // Player could not be authenticated.
        // Disable Game Center in the game.
        logger.log(level: .error,"Error \(error)")
        return
    }
    if GKLocalPlayer.local.isAuthenticated{
        guard GKLocalPlayer.local.scopedIDsArePersistent() else{
            logger.error("Scoped IDs are not persistent, cannot continue with login!")
            return
        }
        Task {
            do{
                let (publicKeyURL, signature, salt, timestamp) = try await GKLocalPlayer.local.fetchItemsForIdentityVerificationSignature()
                print("result: \(publicKeyURL)")
                let json: [String: Any] = [
                    "teamPlayerId":GKLocalPlayer.local.teamPlayerID,
                    "publicKeyURL":publicKeyURL.absoluteString,
                    "signature":signature.base64EncodedString(),
                    "salt":salt.base64EncodedString(),
                    "timestamp":String(timestamp),
                    "alias":GKLocalPlayer.local.alias,
                    "displayName":GKLocalPlayer.local.displayName,
                ]
                let jsonData = try? JSONSerialization.data(withJSONObject: json)
                let url = URL(string: "<directus instance URL>/gamecenter/callback")!
                var request = URLRequest(url: url)
                request.httpMethod = "POST"
                request.httpBody = jsonData
                request.addValue("application/json", forHTTPHeaderField: "Content-Type")
                request.addValue("application/json", forHTTPHeaderField: "Accept")
                let task = URLSession.shared.dataTask(with: request) { data, response, error in
                    logger.debug("Response: \(response), error: \(error)")
                }
                task.resume()
            }
            catch {
                logger.error("Error fetching identifiers")
            }
        }
    }
    else{
        //Should not happen!?
    }
    // Player was successfully authenticated.
    // Check if there are any player restrictions before starting the game.
            
    if GKLocalPlayer.local.isUnderage {
        // Hide explicit game content.
    }


    if GKLocalPlayer.local.isMultiplayerGamingRestricted {
        // Disable multiplayer game features.
    }


    if GKLocalPlayer.local.isPersonalizedCommunicationRestricted {
        // Disable in game communication UI.
    }
    
}

``` 
# Status
This project is nascent and has almost no testing. It involves creating a user in your Directus instance and thus impacts security. I am not a security expert. I am probably the only person using this. I also have limited experience with Directus, so there might be several things wrong with this extension that I am completely unaware of. Use at your own risk, please do not blame me if something, *anything* goes wrong due to this extension.

I'm quite happy to receive suggestions, contributions, issues and discussion about this project, thank you!