// Sshwifty - A Web SSH client
//
// Copyright (C) 2019-2022 Ni Rui <ranqus@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import * as header from "../stream/header.js";
import * as reader from "../stream/reader.js";
import * as stream from "../stream/stream.js";
import * as address from "./address.js";
import * as command from "./commands.js";
import * as common from "./common.js";
import * as controls from "./controls.js";
import * as event from "./events.js";
import Exception from "./exception.js";
import * as history from "./history.js";
import * as presets from "./presets.js";
import * as strings from "./string.js";

const AUTHMETHOD_NONE = 0x00;
const AUTHMETHOD_PASSPHRASE = 0x01;
const AUTHMETHOD_PRIVATE_KEY = 0x02;

const COMMAND_ID = 0x01;

const MAX_USERNAME_LEN = 64;
const MAX_PASSWORD_LEN = 4096;
const DEFAULT_PORT = 22;

const SERVER_REMOTE_STDOUT = 0x00;
const SERVER_REMOTE_STDERR = 0x01;
const SERVER_CONNECT_FAILED = 0x02;
const SERVER_CONNECTED = 0x03;
const SERVER_CONNECT_REQUEST_FINGERPRINT = 0x04;
const SERVER_CONNECT_REQUEST_CREDENTIAL = 0x05;

const CLIENT_DATA_STDIN = 0x00;
const CLIENT_DATA_RESIZE = 0x01;
const CLIENT_CONNECT_RESPOND_FINGERPRINT = 0x02;
const CLIENT_CONNECT_RESPOND_CREDENTIAL = 0x03;

const SERVER_REQUEST_ERROR_BAD_USERNAME = 0x01;
const SERVER_REQUEST_ERROR_BAD_ADDRESS = 0x02;
const SERVER_REQUEST_ERROR_BAD_AUTHMETHOD = 0x03;

const FingerprintPromptVerifyPassed = 0x00;
const FingerprintPromptVerifyNoRecord = 0x01;
const FingerprintPromptVerifyMismatch = 0x02;

const HostMaxSearchResults = 3;

class SSH {
  /**
   * constructor
   *
   * @param {stream.Sender} sd Stream sender
   * @param {object} config configuration
   * @param {object} callbacks Event callbacks
   *
   */
  constructor(sd, config, callbacks) {
    this.sender = sd;
    this.config = config;
    this.connected = false;
    this.events = new event.Events(
      [
        "initialization.failed",
        "initialized",
        "connect.failed",
        "connect.succeed",
        "connect.fingerprint",
        "connect.credential",
        "@stdout",
        "@stderr",
        "close",
        "@completed",
      ],
      callbacks
    );
  }

  /**
   * Send intial request
   *
   * @param {stream.InitialSender} initialSender Initial stream request sender
   *
   */
  run(initialSender) {
    let user = new strings.String(this.config.user),
      userBuf = user.buffer(),
      addr = new address.Address(
        this.config.host.type,
        this.config.host.address,
        this.config.host.port
      ),
      addrBuf = addr.buffer(),
      authMethod = new Uint8Array([this.config.auth]);

    let data = new Uint8Array(userBuf.length + addrBuf.length + 1);

    data.set(userBuf, 0);
    data.set(addrBuf, userBuf.length);
    data.set(authMethod, userBuf.length + addrBuf.length);

    initialSender.send(data);
  }

  /**
   * Receive the initial stream request
   *
   * @param {header.InitialStream} streamInitialHeader Server respond on the
   *                                                   initial stream request
   *
   */
  initialize(streamInitialHeader) {
    if (!streamInitialHeader.success()) {
      this.events.fire("initialization.failed", streamInitialHeader);

      return;
    }

    this.events.fire("initialized", streamInitialHeader);
  }

  /**
   * Tick the command
   *
   * @param {header.Stream} streamHeader Stream data header
   * @param {reader.Limited} rd Data reader
   *
   * @returns {any} The result of the ticking
   *
   * @throws {Exception} When the stream header type is unknown
   *
   */
  tick(streamHeader, rd) {
    switch (streamHeader.marker()) {
      case SERVER_CONNECTED:
        if (!this.connected) {
          this.connected = true;

          return this.events.fire("connect.succeed", rd, this);
        }
        break;

      case SERVER_CONNECT_FAILED:
        if (!this.connected) {
          return this.events.fire("connect.failed", rd);
        }
        break;

      case SERVER_CONNECT_REQUEST_FINGERPRINT:
        if (!this.connected) {
          return this.events.fire("connect.fingerprint", rd, this.sender);
        }
        break;

      case SERVER_CONNECT_REQUEST_CREDENTIAL:
        if (!this.connected) {
          return this.events.fire("connect.credential", rd, this.sender);
        }
        break;

      case SERVER_REMOTE_STDOUT:
        if (this.connected) {
          return this.events.fire("stdout", rd);
        }
        break;

      case SERVER_REMOTE_STDERR:
        if (this.connected) {
          return this.events.fire("stderr", rd);
        }
        break;
    }

    throw new Exception("Unknown stream header marker");
  }

  /**
   * Send close signal to remote
   *
   */
  async sendClose() {
    return await this.sender.close();
  }

  /**
   * Send data to remote
   *
   * @param {Uint8Array} data
   *
   */
  async sendData(data) {
    return this.sender.sendData(CLIENT_DATA_STDIN, data);
  }

  /**
   * Send resize request
   *
   * @param {number} rows
   * @param {number} cols
   *
   */
  async sendResize(rows, cols) {
    let data = new DataView(new ArrayBuffer(4));

    data.setUint16(0, rows);
    data.setUint16(2, cols);

    return this.sender.send(CLIENT_DATA_RESIZE, new Uint8Array(data.buffer));
  }

  /**
   * Close the command
   *
   */
  async close() {
    await this.sendClose();

    return this.events.fire("close");
  }

  /**
   * Tear down the command completely
   *
   */
  completed() {
    return this.events.fire("completed");
  }
}

const initialFieldDef = {
  Password: {
    name: "Password",
    description: "",
    type: "password",
    value: "",
    example: "----------",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      if (d.length <= 0) {
        throw new Error("Password must be specified");
      }

      if (d.length > MAX_PASSWORD_LEN) {
        throw new Error(
          "It's too long, make it shorter than " + MAX_PASSWORD_LEN + " bytes"
        );
      }

      return "We'll login with this password";
    },
  },
  Username: {
    name: "Username",
    description: "",
    type: "text",
    value: "",
    example: "elliot",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      if (d.length <= 0) {
        throw new Error("Username must be specified");
      }

      if (d.length > MAX_USERNAME_LEN) {
        throw new Error(
          "Username must not longer than " + MAX_USERNAME_LEN + " bytes"
        );
      }

      return "We'll login as user \"" + d + '"';
    },
  },
  Host: {
    name: "Host",
    description: "",
    type: "text",
    value: "",
    example: "192.168.1.10",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      if (d.length <= 0) {
        throw new Error("Host must be specified");
      }

      if (d.length > address.MAX_ADDR_LEN) {
        throw new Error(
          "Host must not longer than " + address.MAX_ADDR_LEN + " bytes"
        );
      }

      return "We'll login to \"" + d + '"';
    },
  },
  Pwd: {
    name: "Pwd",
    description: "",
    type: "password",
    value: "",
    example: "----------",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      if (d.length <= 0) {
        throw new Error("Password must be specified");
      }

      if (d.length > MAX_PASSWORD_LEN) {
        throw new Error(
          "It's too long, make it shorter than " + MAX_PASSWORD_LEN + " bytes"
        );
      }

      return "We'll login with this password";
    },
  },

  Fingerprint: {
    name: "Fingerprint",
    description:
      "Please carefully verify the fingerprint. DO NOT continue " +
      "if the fingerprint is unknown to you, otherwise you maybe " +
      "giving your own secrets to an imposter",
    type: "textdata",
    value: "",
    example: "",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      return "";
    },
  },
};

/**
 * Return auth method from given string
 *
 * @param {string} d string data
 *
 * @returns {number} Auth method
 *
 * @throws {Exception} When auth method is invalid
 *
 */
function getAuthMethodFromStr(d) {
  switch (d) {
    case "None":
      return AUTHMETHOD_NONE;

    case "Password":
      return AUTHMETHOD_PASSPHRASE;

    case "Private Key":
      return AUTHMETHOD_PRIVATE_KEY;

    default:
      throw new Exception("Unknown Auth method");
  }
}

class Wizard {
  /**
   * constructor
   *
   * @param {command.Info} info
   * @param {presets.Preset} preset
   * @param {object} session
   * @param {Array<string>} keptSessions
   * @param {streams.Streams} streams
   * @param {subscribe.Subscribe} subs
   * @param {controls.Controls} controls
   * @param {history.History} history
   *
   */
  constructor(
    info,
    preset,
    session,
    keptSessions,
    streams,
    subs,
    controls,
    history
  ) {
    this.info = info;
    this.preset = preset;
    this.hasStarted = false;
    this.streams = streams;
    this.session = session
      ? session
      : {
          credential: "",
        };
    this.keptSessions = keptSessions;
    this.step = subs;
    this.controls = controls.get("SSH");
    this.history = history;
  }

  run() {
    this.step.resolve(this.stepInitialPrompt("SSH", "Secure Shell Host"));
  }

  started() {
    return this.hasStarted;
  }

  control() {
    return this.controls;
  }

  close() {
    this.step.resolve(
      this.stepErrorDone(
        "Action cancelled",
        "Action has been cancelled without reach any success"
      )
    );
  }

  stepErrorDone(title, message) {
    return command.done(false, null, title, message);
  }

  stepSuccessfulDone(data) {
    return command.done(
      true,
      data,
      "Success!",
      "We have connected to the remote"
    );
  }

  stepWaitForAcceptWait() {
    return command.wait(
      "Requesting",
      "Waiting for the request to be accepted by the backend"
    );
  }

  stepWaitForEstablishWait(host) {
    return command.wait(
      "Connecting to " + host,
      "Establishing connection with the remote host, may take a while"
    );
  }

  stepContinueWaitForEstablishWait() {
    return command.wait(
      "Connecting",
      "Establishing connection with the remote host, may take a while"
    );
  }

  /**
   *
   * @param {stream.Sender} sender
   * @param {object} configInput
   * @param {object} sessionData
   *
   */
  buildCommand(sender, configInput, sessionData) {
    let self = this;
    let config = {
      user: common.strToUint8Array(configInput.user),
      username: configInput.username,
      pwd: configInput.pwd,
      auth: getAuthMethodFromStr("Password"),
      charset: configInput.charset,
      credential: sessionData.credential,
      otp: configInput.otp,
      host: address.parseHostPort(configInput.host, DEFAULT_PORT),
      fingerprint: configInput.fingerprint,
    };

    // Copy the keptSessions from the record so it will not be overwritten here
    let keptSessions = self.keptSessions ? [].concat(...self.keptSessions) : [];

    return new SSH(sender, config, {
      "initialization.failed"(hd) {
        switch (hd.data()) {
          case SERVER_REQUEST_ERROR_BAD_USERNAME:
            self.step.resolve(
              self.stepErrorDone("Request failed", "Invalid username")
            );
            return;

          case SERVER_REQUEST_ERROR_BAD_ADDRESS:
            self.step.resolve(
              self.stepErrorDone("Request failed", "Invalid address")
            );
            return;

          case SERVER_REQUEST_ERROR_BAD_AUTHMETHOD:
            self.step.resolve(
              self.stepErrorDone("Request failed", "Invalid authication method")
            );
            return;
        }

        self.step.resolve(
          self.stepErrorDone("Request failed", "Unknown error: " + hd.data())
        );
      },
      initialized(hd) {
        self.step.resolve(self.stepWaitForEstablishWait(configInput.host));
      },
      async "connect.failed"(rd) {
        let d = new TextDecoder("utf-8").decode(
          await reader.readCompletely(rd)
        );

        self.step.resolve(self.stepErrorDone("Connection failed", d));
      },
      "connect.succeed"(rd, commandHandler) {
        self.connectionSucceed = true;

        self.step.resolve(
          self.stepSuccessfulDone(
            new command.Result(
              configInput.user + "@" + configInput.host,
              self.info,
              self.controls.build({
                charset: configInput.charset,
                send(data) {
                  return commandHandler.sendData(data);
                },
                close() {
                  return commandHandler.sendClose();
                },
                resize(rows, cols) {
                  return commandHandler.sendResize(rows, cols);
                },
                events: commandHandler.events,
              }),
              self.controls.ui()
            )
          )
        );

        self.history.save(
          self.info.name() + ":" + configInput.user + "@" + configInput.host,
          configInput.user + "@" + configInput.host,
          new Date(),
          self.info,
          configInput,
          sessionData,
          keptSessions
        );
      },
      async "connect.fingerprint"(rd, sd) {
        self.step.resolve(
          await self.stepFingerprintPrompt(
            rd,
            sd,
            (v) => {
              if (!configInput.fingerprint) {
                return FingerprintPromptVerifyNoRecord;
              }

              if (configInput.fingerprint === v) {
                return FingerprintPromptVerifyPassed;
              }

              return FingerprintPromptVerifyMismatch;
            },
            (newFingerprint) => {
              configInput.fingerprint = newFingerprint;
            }
          )
        );
      },
      async "connect.credential"(rd, sd) {
        sd.send(
          CLIENT_CONNECT_RESPOND_CREDENTIAL,
          new TextEncoder().encode(configInput.otp)
        );
        self.step.resolve(self.stepContinueWaitForEstablishWait());
      },
      "@stdout"(rd) {},
      "@stderr"(rd) {},
      close() {},
      "@completed"() {
        self.step.resolve(
          self.stepErrorDone(
            "Operation has failed",
            "Connection has been cancelled"
          )
        );
      },
    });
  }

  stepInitialPrompt(title, subtitle) {
    let self = this;

    return command.prompt(
      title,
      subtitle,
      "Connect",
      async (r) => {
        let response = await fetch("http://127.0.0.1:8182", {
          method: "POST",
          body: JSON.stringify({
            username: r.username,
            password: r.pwd,
            host: r.host,
          }),
        });
        if (response.status != 200) {
          // Show error message: invalid parameters
          self.step.resolve(
            self.stepInitialPrompt("Error", "Invalid parameters")
          );
          return;
        }

        let responseBody = await response.json();
        let user = responseBody.data.username;
        let otp = responseBody.data.key;
        console.log(otp);
        let host = r.host;
        self.hasStarted = true;

        self.streams.request(COMMAND_ID, (sd) => {
          return self.buildCommand(
            sd,
            {
              user: user,
              username: r.username,
              pwd: r.pwd,
              authentication: "password",
              host: host,
              otp: otp,
              charset: "utf-8",
              fingerprint: self.preset
                ? self.preset.metaDefault("Fingerprint", "")
                : "",
            },
            self.session
          );
        });

        self.step.resolve(self.stepWaitForAcceptWait());
      },
      () => {},
      command.fieldsWithPreset(
        initialFieldDef,
        [{ name: "Username" }, { name: "Pwd" }, { name: "Host" }],
        self.preset,
        (r) => {}
      )
    );
  }

  async stepFingerprintPrompt(rd, sd, verify, newFingerprint) {
    const self = this;

    let fingerprintData = new TextDecoder("utf-8").decode(
        await reader.readCompletely(rd)
      ),
      fingerprintChanged = false;

    switch (verify(fingerprintData)) {
      case FingerprintPromptVerifyPassed:
        sd.send(CLIENT_CONNECT_RESPOND_FINGERPRINT, new Uint8Array([0]));

        return self.stepContinueWaitForEstablishWait();

      case FingerprintPromptVerifyMismatch:
        fingerprintChanged = true;
    }

    return command.prompt(
      !fingerprintChanged
        ? "Do you recognize this server?"
        : "Danger! Server fingerprint has changed!",
      !fingerprintChanged
        ? "Verify server fingerprint displayed below"
        : "It's very unusual. Please verify the new server fingerprint below",
      !fingerprintChanged ? "Yes, I do" : "I'm aware of the change",
      (r) => {
        newFingerprint(fingerprintData);

        sd.send(CLIENT_CONNECT_RESPOND_FINGERPRINT, new Uint8Array([0]));

        self.step.resolve(self.stepContinueWaitForEstablishWait());
      },
      () => {
        sd.send(CLIENT_CONNECT_RESPOND_FINGERPRINT, new Uint8Array([1]));

        self.step.resolve(
          command.wait("Rejecting", "Sending rejection to the backend")
        );
      },
      command.fields(initialFieldDef, [
        {
          name: "Fingerprint",
          value: fingerprintData,
        },
      ])
    );
  }
}

class Executer extends Wizard {
  /**
   * constructor
   *
   * @param {command.Info} info
   * @param {config} config
   * @param {object} session
   * @param {Array<string>} keptSessions
   * @param {streams.Streams} streams
   * @param {subscribe.Subscribe} subs
   * @param {controls.Controls} controls
   * @param {history.History} history
   *
   */
  constructor(
    info,
    config,
    session,
    keptSessions,
    streams,
    subs,
    controls,
    history
  ) {
    super(
      info,
      presets.emptyPreset(),
      session,
      keptSessions,
      streams,
      subs,
      controls,
      history
    );

    this.config = config;
  }

  stepInitialPrompt() {
    const self = this;

    self.hasStarted = true;

    self.streams.request(COMMAND_ID, (sd) => {
      return self.buildCommand(
        sd,
        {
          user: self.config.user,
          username: self.config.username,
          otp: self.config.otp,
          pwd: self.config.pwd,
          authentication: self.config.authentication,
          host: self.config.host,
          charset: self.config.charset ? self.config.charset : "utf-8",
          fingerprint: self.config.fingerprint,
        },
        self.session
      );
    });

    return self.stepWaitForAcceptWait();
  }
}

export class Command {
  constructor() {}

  id() {
    return COMMAND_ID;
  }

  name() {
    return "SSH";
  }

  description() {
    return "Secure Shell Host";
  }

  color() {
    return "#3c8";
  }

  wizard(
    info,
    preset,
    session,
    keptSessions,
    streams,
    subs,
    controls,
    history
  ) {
    return new Wizard(
      info,
      preset,
      session,
      keptSessions,
      streams,
      subs,
      controls,
      history
    );
  }

  execute(
    info,
    config,
    session,
    keptSessions,
    streams,
    subs,
    controls,
    history
  ) {
    return new Executer(
      info,
      config,
      session,
      keptSessions,
      streams,
      subs,
      controls,
      history
    );
  }

  launch(info, launcher, streams, subs, controls, history) {
    const d = launcher.split("|", 3);

    if (d.length < 2) {
      throw new Exception('Given launcher "' + launcher + '" was invalid');
    }

    const userHostName = d[0].match(new RegExp("^(.*)\\@(.*)$"));

    if (!userHostName || userHostName.length !== 3) {
      throw new Exception('Given launcher "' + launcher + '" was malformed');
    }

    let user = userHostName[1],
      host = userHostName[2],
      auth = d[1],
      charset = d.length >= 3 && d[2] ? d[2] : "utf-8"; // RM after depreciation

    /*
    try {
      initialFieldDef["User"].verify(user);
      initialFieldDef["Host"].verify(host);
      initialFieldDef["Authentication"].verify(auth);
    } catch (e) {
      throw new Exception(
        'Given launcher "' + launcher + '" was malformed ' + e
      );
    }
    */

    return this.execute(
      info,
      {
        user: user,
        host: host,
        authentication: auth,
        charset: charset,
      },
      null,
      null,
      streams,
      subs,
      controls,
      history
    );
  }

  launcher(config) {
    return (
      config.user +
      "@" +
      config.host +
      "|" +
      config.authentication +
      "|" +
      (config.charset ? config.charset : "utf-8")
    );
  }

  represet(preset) {
    const host = preset.host();

    if (host.length > 0) {
      preset.insertMeta("Host", host);
    }

    return preset;
  }
}
