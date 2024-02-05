title = "JASMIN";

description = `
The elephants
are loose!
`;

options = {
  isPlayingBgm: true,
  seed: 2508,
};

characters = [
`
 y  Y
yyy  Y
yCCy Y
yyCCyY
 yyCyY
   yyY
`,
`
 Y  y
Y  yyy
Y yCCy
YyCCyy
YyCyy
Yyy
`,
`
  yyyY
 yPPyY
yPPPyY
yPPPyY
yPPy Y
 yy  Y
`,
`
Yyyy
YyPPy
YyPPPy
YyPPPy
Y yPPy
Y  yy
`,
`
RR  RR
RRRRRR
RRRRRR
 RRRR
  RRR
   R
`,
`
llllll
l llll
llllll
llllll
ll l l
l  l l
`

]

/** @typedef {"HIGH" | "BASE" | "LOW" | "LOWER"} Lane*/

/** @typedef {Object} Entity
 *  @property {() => void} update
 *  @property {Lane} lane
 *  @property {number} x
 *  @property {boolean} dirty
 *  @property {string} char
 */

const p = {};

let spawnTicks = 60;
/** @type {Entity[]}*/
let entities;

const updateSelf = function() {
  this.x -= 0.5 * difficulty;
  if (this.x < 0) this.dirty = true;
}

const getRandomLane = () => {
  const lanes = ["HIGH", "BASE", "LOW", "LOWER"];
  const i = rndi(4);
  return lanes[i]
}

const positions = {
  "HIGH": 20,
  "BASE": 40,
  "LOW": 60,
  "LOWER": 80,
}

const updatePlayer = (inputPos) => {
  const prevLane = p.lane;

  switch (p.lane) {
    case "HIGH":
      if (inputPos.y > 30) p.lane = "BASE";
      break;
    case "BASE":
      if (inputPos.y > 50) p.lane = "LOW";
      if (inputPos.y < 30) p.lane = "HIGH";
      break;
    case "LOW":
      if (inputPos.y > 70) p.lane = "LOWER";
      if (inputPos.y < 50) p.lane = "BASE";
      break;
    case "LOWER":
      if (inputPos.y < 70) p.lane = "LOW";
      break;
  }

  // Play a sound if player switched lanes.
  if (p.lane !== prevLane) play("select");
}

function update() {
  if (!ticks) {
    p.lane= "BASE";
    p.x = 20;
    p.y = positions[p.lane]-3;
    entities = [];
  }

  spawnTicks--;
  if (spawnTicks === 0) {
    // Spawn a random entity, either elepahnt or heart.
    const lane = getRandomLane()
    const x = 100;
    const char = rndi(2) === 0 ? "e" : "f";
    spawnTicks = 60;
    const entity = {
      char,
      lane,
      x,
      update: updateSelf,
      dirty: false,
    }
    entities.push(entity);
  }

  // Quarter million, switchin' lanes.
  if (input.isJustPressed) {
    updatePlayer(input.pos);
    p.y = positions[p.lane]-3;
  }

  // Draw every player sprite.
  char("a", p.x, p.y);
  char("b", p.x+6, p.y);
  char("c", p.x, p.y+6);
  char("d", p.x+6, p.y+6);

  // Update and draw every entity.
  entities.forEach(e => {
    e.update();
    const y = positions[e.lane]
    if (char(e.char, e.x, y).isColliding.char.d) {
      if (e.char === "e") {
        e.dirty = true;
        color("light_red");
        particle(e.x, positions[e.lane], 100, 2);
        color("black");
        play("coin")
        addScore(floor(difficulty), e.x, positions[e.lane]);
      } else if (e.char === "f") {
        play("hit");
        end();
      }
    }
  })

  remove(entities, e => {
    return e.dirty;
  })

  // Draw the lanes.
  color("light_purple");
  line(0, 10, 100, 10, 2);
  line(0, 30, 100, 30, 2);
  line(0, 50, 100, 50, 2);
  line(0, 70, 100, 70, 2);
  line(0, 90, 100, 90, 2);
  color("black");
}
