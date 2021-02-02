/*
 * Copyright (c) 2015-2019 The Decred developers
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package btclibwallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/decred/dcrwallet/errors/v2"
)

var wordList = strings.Split(AlternatingWords, "\n")
var wordIndexes = make(map[string]uint16, len(wordList))

func init() {
	for i, word := range wordList {
		wordIndexes[strings.ToLower(strings.TrimSpace(word))] = uint16(i)
	}
}

func PGPWordList() []string {
	return wordList
}

// ByteToMnemonic returns the PGP word list encoding of b when found at index.
func ByteToMnemonic(b byte, index int) string {
	bb := uint16(b) * 2
	if index%2 != 0 {
		bb++
	}
	return wordList[bb]
}

// EncodeMnemonic encodes a seed as a mnemonic word list separated by spaces.
func EncodeMnemonic(seed []byte) string {
	var buf bytes.Buffer
	for i, b := range seed {
		if i != 0 {
			buf.WriteRune(' ')
		}
		buf.WriteString(ByteToMnemonic(b, i))
	}
	checksum := checksumByte(seed)
	buf.WriteRune(' ')
	buf.WriteString(ByteToMnemonic(checksum, len(seed)))
	return buf.String()
}

// DecodeMnemonics returns the decoded value that is encoded by words.  Any
// words that are whitespace are empty are skipped.
func DecodeMnemonics(words []string) ([]byte, error) {
	const op errors.Op = "pgpwordlist.DecodeMnemonics"

	decoded := make([]byte, len(words))
	idx := 0
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		b, ok := wordIndexes[strings.ToLower(w)]
		if !ok {
			err := errors.Errorf("word '%v' is not in the PGP word list", w)
			return nil, errors.E(op, errors.Encoding, err)
		}
		if int(b%2) != idx%2 {
			err := errors.Errorf("word '%v' is not valid at position %v, "+
				"check for missing words", w, idx)
			return nil, errors.E(op, errors.Encoding, err)
		}
		decoded[idx] = byte(b / 2)
		idx++
	}
	return decoded[:idx], nil
}

// DecodeUserInput decodes a seed in either hexadecimal or mnemonic word list
// encoding back into its binary form.
func DecodeUserInput(input string) ([]byte, error) {
	const op errors.Op = "walletseed.DecodeUserInput"
	words := strings.Split(strings.TrimSpace(input), " ")
	var seed []byte
	switch {
	case len(words) == 1:
		// Assume hex
		var err error
		seed, err = hex.DecodeString(words[0])
		if err != nil {
			return nil, errors.E(op, errors.Encoding, err)
		}
	case len(words) > 1:
		// Assume mnemonic with encoded checksum byte
		decoded, err := DecodeMnemonics(words)
		if err != nil {
			return nil, errors.E(op, errors.Encoding, err)
		}
		if len(decoded) < 2 { // need data (0) and checksum (1) to check checksum
			break
		}
		if checksumByte(decoded[:len(decoded)-1]) != decoded[len(decoded)-1] {
			return nil, errors.E(op, errors.Encoding, "checksum mismatch")
		}
		seed = decoded[:len(decoded)-1]
	}

	if len(seed) < hdkeychain.MinSeedBytes || len(seed) > hdkeychain.MaxSeedBytes {
		return nil, errors.E(op, errors.Encoding, hdkeychain.ErrInvalidSeedLen)
	}
	return seed, nil
}

func checksumByte(data []byte) byte {
	intermediateHash := sha256.Sum256(data)
	return sha256.Sum256(intermediateHash[:])[0]
}

const AlternatingWords = `aardvark
adroitness
absurd
adviser
accrue
aftermath
acme
aggregate
adrift
alkali
adult
almighty
afflict
amulet
ahead
amusement
aimless
antenna
Algol
applicant
allow
Apollo
alone
armistice
ammo
article
ancient
asteroid
apple
Atlantic
artist
atmosphere
assume
autopsy
Athens
Babylon
atlas
backwater
Aztec
barbecue
baboon
belowground
backfield
bifocals
backward
bodyguard
banjo
bookseller
beaming
borderline
bedlamp
bottomless
beehive
Bradbury
beeswax
bravado
befriend
Brazilian
Belfast
breakaway
berserk
Burlington
billiard
businessman
bison
butterfat
blackjack
Camelot
blockade
candidate
blowtorch
cannonball
bluebird
Capricorn
bombast
caravan
bookshelf
caretaker
brackish
celebrate
breadline
cellulose
breakup
certify
brickyard
chambermaid
briefcase
Cherokee
Burbank
Chicago
button
clergyman
buzzard
coherence
cement
combustion
chairlift
commando
chatter
company
checkup
component
chisel
concurrent
choking
confidence
chopper
conformist
Christmas
congregate
clamshell
consensus
classic
consulting
classroom
corporate
cleanup
corrosion
clockwork
councilman
cobra
crossover
commence
crucifix
concert
cumbersome
cowbell
customer
crackdown
Dakota
cranky
decadence
crowfoot
December
crucial
decimal
crumpled
designing
crusade
detector
cubic
detergent
dashboard
determine
deadbolt
dictator
deckhand
dinosaur
dogsled
direction
dragnet
disable
drainage
disbelief
dreadful
disruptive
drifter
distortion
dropper
document
drumbeat
embezzle
drunken
enchanting
Dupont
enrollment
dwelling
enterprise
eating
equation
edict
equipment
egghead
escapade
eightball
Eskimo
endorse
everyday
endow
examine
enlist
existence
erase
exodus
escape
fascinate
exceed
filament
eyeglass
finicky
eyetooth
forever
facial
fortitude
fallout
frequency
flagpole
gadgetry
flatfoot
Galveston
flytrap
getaway
fracture
glossary
framework
gossamer
freedom
graduate
frighten
gravity
gazelle
guitarist
Geiger
hamburger
glitter
Hamilton
glucose
handiwork
goggles
hazardous
goldfish
headwaters
gremlin
hemisphere
guidance
hesitate
hamlet
hideaway
highchair
holiness
hockey
hurricane
indoors
hydraulic
indulge
impartial
inverse
impetus
involve
inception
island
indigo
jawbone
inertia
keyboard
infancy
kickoff
inferno
kiwi
informant
klaxon
insincere
locale
insurgent
lockup
integrate
merit
intention
minnow
inventive
miser
Istanbul
Mohawk
Jamaica
mural
Jupiter
music
leprosy
necklace
letterhead
Neptune
liberty
newborn
maritime
nightbird
matchmaker
Oakland
maverick
obtuse
Medusa
offload
megaton
optic
microscope
orca
microwave
payday
midsummer
peachy
millionaire
pheasant
miracle
physique
misnomer
playhouse
molasses
Pluto
molecule
preclude
Montana
prefer
monument
preshrunk
mosquito
printer
narrative
prowler
nebula
pupil
newsletter
puppy
Norwegian
python
October
quadrant
Ohio
quiver
onlooker
quota
opulent
ragtime
Orlando
ratchet
outfielder
rebirth
Pacific
reform
pandemic
regain
Pandora
reindeer
paperweight
rematch
paragon
repay
paragraph
retouch
paramount
revenge
passenger
reward
pedigree
rhythm
Pegasus
ribcage
penetrate
ringbolt
perceptive
robust
performance
rocker
pharmacy
ruffled
phonetic
sailboat
photograph
sawdust
pioneer
scallion
pocketful
scenic
politeness
scorecard
positive
Scotland
potato
seabird
processor
select
provincial
sentence
proximate
shadow
puberty
shamrock
publisher
showgirl
pyramid
skullcap
quantity
skydive
racketeer
slingshot
rebellion
slowdown
recipe
snapline
recover
snapshot
repellent
snowcap
replica
snowslide
reproduce
solo
resistor
southward
responsive
soybean
retraction
spaniel
retrieval
spearhead
retrospect
spellbind
revenue
spheroid
revival
spigot
revolver
spindle
sandalwood
spyglass
sardonic
stagehand
Saturday
stagnate
savagery
stairway
scavenger
standard
sensation
stapler
sociable
steamship
souvenir
sterling
specialist
stockman
speculate
stopwatch
stethoscope
stormy
stupendous
sugar
supportive
surmount
surrender
suspense
suspicious
sweatband
sympathy
swelter
tambourine
tactics
telephone
talon
therapist
tapeworm
tobacco
tempest
tolerance
tiger
tomorrow
tissue
torpedo
tonic
tradition
topmost
travesty
tracker
trombonist
transit
truncated
trauma
typewriter
treadmill
ultimate
Trojan
undaunted
trouble
underfoot
tumor
unicorn
tunnel
unify
tycoon
universe
uncut
unravel
unearth
upcoming
unwind
vacancy
uproot
vagabond
upset
vertigo
upshot
Virginia
vapor
visitor
village
vocalist
virus
voyager
Vulcan
warranty
waffle
Waterloo
wallet
whimsical
watchword
Wichita
wayside
Wilmington
willow
Wyoming
woodlark
yesteryear
Zulu
Yucatan`
