# lastpass-ssh-agent

**Disclaimer: this program is experimental. Don't use it for now if you're security-conscious, as it cuts a few corners that might leak your unencrypted private keys to RAM and swap.**

## What

lastpass-ssh-agent is an ssh agent that authenticates you using keys stored as secure notes from your lastpass vault.

## Why

Other solutions usually feed your keys from lastpass to ssh-add, which is not ideal as it doesn't get updated with lastpass changes, and requires a manual call to the program.

Some even expect you to store your private key passphrase in lastpass, while leaving up to you the storage of your key pairs, and expecting you to have them in your `~/.ssh`. 

Instead, lastpass-ssh-agent expect you to put your public key and unencrypted private key in a secure note on lastpass under `keys\ssh`. It being an ssh agent, it integrates perfectly with the ssh command, and will ask your vault password when needed.

## Building

lastpass-ssh-agent depends on [lastpass-cli](https://github.com/lastpass/lastpass-cli), openssl, and autotools.

To build it, clone this repository, and execute the following instructions:

```sh
$ autoreconf -i .
$ mkdir build && cd $_
$ ../configure --prefix=/usr
$ make
$ sudo make install
```

## Usage

During session startup, you need to:

* run/daemonize `lastpass-ssh-agent`
* `export SSH_AUTH_SOCK="/run/user/$(id -u)/lastpass-ssh-agent/agent.sock"`

And that's pretty much it. Now, you just need to add your keys to lastpass under `keys\ssh` (make sure that the private key is unencrypted), and you're good to go.

## F.A.Q

**Q.** Why do I need to put my private keys unencrypted into lastpass?  
**A.** Because lastpass already encrypts them for you; storing the passphrase alongside the encrypted private key is effectively defeating the purpose of encrypting them, so we're just dropping the passphrase.  
