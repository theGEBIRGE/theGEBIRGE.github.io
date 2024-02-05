title = "OFFGRID";

description = `
Tap to shrink
`;

options = {
  isPlayingBgm: true,
  seed: 90,
};

/** @typedef {Object} rectangle
 *  @property {Vector} pos
 *  @property {Vector} initPos
 *  @property {number} w
 *  @property {string} c
 *  @property {number} expandTicks
 *  @property {() => void} shrink
 *  @property {() => void} update
 */

/** @type {{
      pos: Vector,
    }}
 */
let p;
// @type {rectangle[]}
let rects;
let spawnTicks;
let screenClearCounter;

let MIN_WIDTH = 15;

const updateRect = function() {
  if (this.expandTicks < 0) {
    // Reset the screen clear square.
    if (this.c == "yellow") {
      this.c = "red"
    }
    play("hit")
    this.expandTicks = 60-difficulty*4
    this.pos.sub(vec(1, 1));
    this.w += 2;
  }
  this.expandTicks--;
}

const shrink = function() {
  if (this.c !== "red") return;
  if (this.w === MIN_WIDTH) {
    play("coin");
    // We want fireworks if we reach the initial position :).
    particleNum = 100;
    this.c = "black";
    color("black")
    particle(vec(this.pos.x + (this.w / 2), this.pos.y + (this.w / 2)), 100, 2);
    this.update = undefined;
  } else {
    play("select");
    this.pos.add(vec(1,1));
    this.w -= 2;
    color("red");
    particle(vec(this.pos.x + (this.w / 2), this.pos.y + (this.w / 2)), 50, 2);
  }
  addScore(this.w + difficulty)
  this.expandTicks = 120-difficulty*4;
}

const getRandomBlackSquareIndex = function() {
  const blackIndices = [];
  rects.forEach((r, i) => {
    if (r.c === "black") {
      blackIndices.push(i);
    }
  })

  // Game over if the screen is filled with red squares.
  if (blackIndices.length < 1) {
    return undefined;
  }

  // Pick a random one.
  const randomIndex = rndi(blackIndices.length-1);
  return blackIndices[randomIndex];
}

function update() {
  if (!ticks) {
    // Create the play field.
    const startX = 12;
    const startY = 15;
    const xOffset = 20;
    const yOffset = 20;
    rects = [];
    for (let i=0; i<4; i++) {
      for (let j=0; j<4; j++) {
        const rect = {
          pos: vec(startX + xOffset*i, startY+ yOffset*j),
          initPos: vec(startX + xOffset*i, startY + yOffset*j),
          w: 15,
          expandTicks: 45-difficulty*4,
          c: "black",
          shrink,
        }
        rects.push(rect);
      }
    }
    // Our player object just holds a position.
    p = {pos: vec(40,40)}
    // Initialize some timers.
    spawnTicks = 35-difficulty*4;
    screenClearCounter = rndi(12, 14+difficulty);
  }

  if (spawnTicks < 0) {
    screenClearCounter--;
    let color = "red";
    if (screenClearCounter < 1) {
      screenClearCounter = rndi(12, 14+difficulty);
      color = "yellow";
    }
    spawnTicks = 35-difficulty*4;

    const i = getRandomBlackSquareIndex();
    if (i === undefined) {
      end();
      // This is important, otherwise the update function will continue
      // and throw an error.
      return;
    }

    // Have some variety in sizes.
    const heads = rndi(0, 2);
    if (heads) {
      rects[i].w += 2;
      rects[i].pos.sub(vec(1, 1));
    }

    rects[i].c = color;
    rects[i].update = updateRect;
    play("hit");
  }

  if (input.isJustPressed) {
    p.pos = input.pos;
  } else {
    p.pos = vec(0, 0);
  }

  rects.forEach(r => {
    if (r.update) r.update();

    if (r.c == "red") {
      if (rect(r.pos, r.w).isColliding.rect.black) {
        end();
      }
      if (p.pos.isInRect(r.pos.x, r.pos.y, r.w, r.w)) {
        // The player hit the rectangle.
        r.shrink();
      }
    }

    if (r.c == "yellow") {
      if (p.pos.isInRect(r.pos.x, r.pos.y, r.w, r.w)) {
        // Screen clear, aka shrink every square.
        color("yellow");
        particle(vec(50, 50), 5000, 4);
        play("powerUp");

        r.c = "red";
        r.pos = vec(r.initPos);
        r.w = MIN_WIDTH;
        rects.forEach(r => r.shrink());
      }

    }
    color(r.c);
    rect(r.pos, r.w);
  })

  spawnTicks--;
}
