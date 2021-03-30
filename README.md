# GPG Verify

Testing code to verify GPG without needing GPG, in Python. The start of
this script is derived from [this gist](https://gist.github.com/mrmekon/1348090/7b09558e01300cdd3f7cb36973aa31427e787775)
with an Apache license. The [original license](LICENSE.original) is included
here along with the [LICENSE](LICENSE),

## Test Environment

First let's set up a dummy case of creating a key, signing something,
and then we can try to verify it. GitHub actually has [nice documentation](https://docs.github.com/en/github/authenticating-to-github/generating-a-new-gpg-key)
for this. If you already have one, you can just list them:

```bash
$ gpg --list-secret-keys --keyid-format LONG
```

Let's make a file to sign.

```bash
$ echo "TACOS?" > tacos.txt
```

And sign it!

```bash
$ gpg --sign tacos.txt
```

That generates a file with extension gpg.
You can try verifying it, just as a sanity check:

```bash
$ gpg --verify tacos.txt.gpg 
gpg: Signature made Mon 29 Mar 2021 01:03:01 PM MDT
gpg:                using RSA key 9C48AA932DE7FC1056E6F4768C9BC1XXXXXXXXXX
gpg: Good signature from "dinosaur <dinosaur@dinosaurthings.com>" [ultimate]
```

## Python Verify

Now let's write a script that will read in the binary of the file,
and try to verify it. I was at first looking at 
[RedHat's rpm verify](https://github.com/rpm-software-management/rpm/blob/551e66fc94668e62910008d047428eb5ec62f896/lib/verify.c)
and [the gpg source code](https://github.com/gpg/gnupg/blob/7f3ce66ec56a5aea6170b7eb1bda5626eb208c83/g10/mainproc.c) 
but I found the best documentation to be [the ref standard](https://tools.ietf.org/html/rfc4880#section-4.1)
for it instead.

```bash
$ python verify.py tacos.txt.gpg
```
