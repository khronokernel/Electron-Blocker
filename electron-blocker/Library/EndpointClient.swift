/*
    Endpoint Security Client
    ------------------------
    Heavily based on Brandon7CC's ESClient.swift:
    - https://github.com/Brandon7CC/mac-wheres-my-bootstrap

    Apple Reference Documentation:
    - https://developer.apple.com/documentation/endpointsecurity
 */

import Foundation
import EndpointSecurity


class EndpointSecurityClient: NSObject {

    var endpointClient: OpaquePointer?

    /*
        Start Endpoint Security client
    */
    public func start() {
        self.endpointClient = initializeEndpointClient()
    }


    /*
        Stop Endpoint Security client
    */
    public func stop() {
        es_delete_client(self.endpointClient)
    }

    /*
        Convert es_event_exec_t arguments to Swift array of strings

        - Parameters:
            - event: es_event_exec_t event

        - Returns: Array of strings
    */
    private func esEventArguments(event: inout es_event_exec_t) -> [String] {
        return (0 ..< Int(es_exec_arg_count(&event))).map {
            String(cString: es_exec_arg(&event, UInt32($0)).data)
        }
    }


    /*
        Convert es_event_exec_t environment variables to Swift array of strings

        - Parameters:
            - event: es_event_exec_t event

        - Returns: Array of strings
     */
    private func esEventEnvironmentVariables(event: inout es_event_exec_t) -> [String] {
        return (0 ..< Int(es_exec_env_count(&event))).map {
            String(cString: es_exec_env(&event, UInt32($0)).data)
        }
    }


    private func isElectronApplication(executablePath: String) -> Bool {

        if !FileManager.default.fileExists(atPath: executablePath) {
            return false
        }

        let pathComponents = executablePath.components(separatedBy: "/")
        if pathComponents.count < 3 {
            return false
        }

        let electronExecutablePath = pathComponents.dropLast(2).joined(separator: "/") + "/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"
        if !FileManager.default.fileExists(atPath: electronExecutablePath) {
            return false
        }

        return true
    }


    /*
        Check for malicious arguments

        - Parameters:
            - arguments: Array of strings

        - Returns: Bool
     */
    private func hasMaliciousArguments(_ arguments: [String]) -> Bool {
        if arguments.contains(where: { $0.starts(with: "--inspect=") }) {
            return true
        }
        if arguments.contains(where: { $0.starts(with: "--inspect-brk=") }) {
            return true
        }
        if arguments.contains(where: { $0.starts(with: "--inspect-wait=") }) {
            return true
        }

        if arguments.contains("inspect") {
            if let index = arguments.firstIndex(of: "inspect") {
                if index + 1 < arguments.count {
                    let nextArgument = arguments[index + 1]
                    if nextArgument.starts(with: "--port=") {
                        return true
                    }
                }
            }
        }

        if arguments.contains("inspect") {
            if let index = arguments.firstIndex(of: "inspect") {
                if index + 1 < arguments.count {
                    return true
                }
            }
        }

        return false

    }


    /*
        Check for malicious environment variables

        - Parameters:
            - environmentVariables: Array of strings

        - Returns: Bool
    */
    private func hasMaliciousEnvironmentVariables(_ environmentVariables: [String]) -> Bool {
        for environmentVariable in environmentVariables {
            if !environmentVariable.starts(with: "ELECTRON_RUN_AS_NODE") {
                continue
            }

            if !environmentVariable.contains("=") {
                continue
            }

            let components = environmentVariable.components(separatedBy: "=")
            if components.count < 2 {
                continue
            }

            let value = components[1]
            if value.contains("1") {
                return true
            }
            if value.contains("true") {
                return true
            }
        }

        return false
    }


    /*
        Process Endpoint Security event

        - Parameters:
            - event: UnsafePointer<es_message_t> event
    */
    private func processEvent(event: UnsafePointer<es_message_t>) {
        if event.pointee.event_type != ES_EVENT_TYPE_AUTH_EXEC {
            return
        }

        let executablePath = String(cString: event.pointee.process.pointee.executable.pointee.path.data)

        var mutableEvent = event.pointee.event.exec

        let arguments = esEventArguments(event: &mutableEvent)
        if arguments.count < 1 {
            es_respond_auth_result(self.endpointClient!, event, ES_AUTH_RESULT_ALLOW, true)
            return
        }

        let isElectronApp = isElectronApplication(executablePath: arguments[0])
        if !isElectronApp {
            es_respond_auth_result(self.endpointClient!, event, ES_AUTH_RESULT_ALLOW, true)
            return
        }

        let environmentVariables = esEventEnvironmentVariables(event: &mutableEvent)


        let maliciousArguments = hasMaliciousArguments(arguments)
        let maliciousEnvironmentVariables = hasMaliciousEnvironmentVariables(environmentVariables)

        if !maliciousArguments && !maliciousEnvironmentVariables {
            es_respond_auth_result(self.endpointClient!, event, ES_AUTH_RESULT_ALLOW, true)
            return
        }

        print("Malicious Electron Application detected!")
        print("  Executable Path: \(executablePath)")
        print("  Arguments: \(arguments)")
        print("  Environment Variables: \(environmentVariables)")


        print("Rejecting authorization...")

        es_respond_auth_result(self.endpointClient!, event, ES_AUTH_RESULT_DENY, true)
    }


    /*
        Determine error upon creating a new Endpoint Security client

        - Parameters:
            - result: es_new_client_result_t result

        - Returns: String message
    */
    private func processNewClientCreation(result: es_new_client_result_t) -> String {
        var message: String = ""
        switch result {
            case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
                message = "More than 50 Endpoint Security clients are connected!"
                break
            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
                message = "Executable is missing com.apple.developer.endpoint-security.client entitlement!"
                break
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
                message = "Parent is missing Full Disk Access permission!"
                break
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
                message = "Parent is not running as root!"
                break
            case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
                message = "Internal Endpoint Security error!"
                break
            case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
                message = "Incorrect arguments to create Endpoint Security client!"
                break
            case ES_NEW_CLIENT_RESULT_SUCCESS:
                break
            default:
                message = "An unknown error occurred while creating a new Endpoint Security client!"
        }

        return message
    }


    /*
        Initialize Endpoint Security client

        - Returns: OpaquePointer to Endpoint Security client
    */
    private func initializeEndpointClient() -> OpaquePointer? {
        var client: OpaquePointer?

        let initResult: es_new_client_result_t = es_new_client(&client){ _, event in
            self.processEvent(event: event)
        }

        let message = processNewClientCreation(result: initResult)
        if message != "" {
            print(message)
            exit(EXIT_FAILURE)
        }

        let subsriptions = [
            ES_EVENT_TYPE_AUTH_EXEC
        ]

        if es_subscribe(client!, subsriptions, UInt32(subsriptions.count)) != ES_RETURN_SUCCESS {
            print("Failed to subscribe to ES_EVENT_TYPE_AUTH_EXEC event!")
            es_delete_client(client)
            exit(EXIT_FAILURE)
        }

        return client
    }
}
