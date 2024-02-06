const title = "DONEWELL";

const description = `
DO WELL!
`;

const characters = [
  `
llllll
ll l l
ll l l
llllll
 l  l
  `,
  `
llllll
l l ll
l l ll
llllll
 l  l
  `,
];

const options = {
  isPlayingBgm: true,
  seed: 12343,
};

/** @typedef {Object} block
 *  @property {Vector} pos
 *  @property {Vector} vel
 *  @property {number} w
 *  @property {string} col
 *  @property {boolean} dirty
 *  @property {() => void} explode
 */

/** @type {{
      pos: Vector,
      prevPos: Vector,
      vel: Vector,
      animation: string,
    }}
 */

let p;
/** @type {block[]} */
let blocks;
/** @type {number} */
let g;
/** @type {number} */
let redTicks;
/** @type {number} */
let blackTicks;

function update() {
  if (!ticks) {
    p = {
      pos: vec(45, 10),
      animation: "a",
      vel: vec(),
      prevPos: vec(30, 10)
    };

    blocks = [];
    g = 0.05;
    redTicks = rndi(5, 11);
    blackTicks = 0;
  }

  blackTicks--;

  if (blackTicks < 1) {
    blackTicks = 31 - difficulty * 2;
    redTicks--;
    const x = rndi(5, 90);
    let velY = rnd(0.25 * difficulty, 0.5 * difficulty);
    velY = clamp(velY, 0, 0.6);
    let w = rndi(10 - floor(difficulty * 2), 13 - floor(difficulty * 2));
    w = clamp(w, 4, w);

    let b = {
      pos: vec(x, 100),
      w,
      vel: vec(0, velY),
    };
    // Add properties unique to black or red blocks.
    if (redTicks === 0) {
      redTicks = rndi(5, 11);
      b.col = "red";
      b.explode = () => particle(vec(b.pos.x + (b.w / 2), b.pos.y), 1000, 2.5);
    } else {
      b.col = "black";
      b.explode = () => particle(vec(b.pos.x + (b.w / 2), b.pos.y));
    }
    blocks.push(b);
  }

  // Which direction is the player facing?
  p.prevPos.x < p.pos.x ? p.animation = "a" : p.animation = "b";
  color("black");
  char(p.animation, p.pos);

  // Update every block.
  blocks.forEach(b => {
    b.pos.sub(b.vel)

    // Game over if block reaches top of the screen.
    if (b.pos.y <= 0) {
      b.dirty = true;
      color("yellow");
      particle(vec(b.pos.x + 5, b.pos.y + 5), 1000, 2);
      play("explosion");
      // We want to be able to see the explosion.
      setTimeout(() => end(), 300);
      return;
    }

    color(b.col);
    if (rect(b.pos.x, b.pos.y, b.w, 3).isColliding.char[p.animation]) {
      play("jump");
      if (p.pos.y > 74) {
        p.vel = vec(0, -1.6);
      } else {
        p.vel = vec(0, -1.2);
      }
      b.dirty = true;

      // Clear the screen by setting all blocks to dirty after
      // colliding with a red block.
      if (b.col === "red") {
        const newBlocks = blocks.map(b => {
          const newBlock = {...b};
          newBlock.dirty = true;
          return newBlock;
        })
        blocks = newBlocks;
        play("powerUp");
        blackTicks = 10;
      }
    }
  })

  // Remove every dirty block.
  // We increment a bonus value for every block that's on screen.
  let bonus = 0;
  remove(blocks, (b) => {
    if (!b.dirty) return false;
    if (b.col === "red") {
      addScore(5 + bonus, vec(b.pos.x, b.pos.y + 5));
      color("red");
    } else {
      addScore(1 + bonus, vec(b.pos.x, b.pos.y + 5));
      color("black");
    }
    b.explode();
    bonus++;
    return true;
  })

  // We gradually move towards the player's input position,
  // but stay within the limits of the screen.
  if (input.isPressed) {
    const tmpX = p.pos.x + (input.pos.x - p.pos.x) * 0.15;
    p.prevPos = vec(p.pos);
    p.pos.x = clamp(tmpX, 5, 95);
  }

  p.vel.add(0, g);
  p.pos.add(p.vel);

  // Game over if the player hits the ground.
  if (p.pos.y > 100) {
    play("hit");
    end();
  }
}
