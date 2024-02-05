title = "HOTSHOT";

description = `
HOLD
 to slow down
RELEASE
 to shoot
`;

options = {
  isPlayingBgm: true,
  seed: 1989,
  isCapturing: true,
};

let targets = [];
let bullet = null;
let lifes;
let SLOWMO = 0;
const BASE_SPEED = 1;

const lifeLines = [
  () => line(40, 95, 60, 95, 3),
  () => line(45, 90, 55, 90, 3),
  () => line(48, 85, 52, 85, 3),
];

const muzzleFlashes = [
  () => particle(50, 85, 20, 0.6),
  () => particle(50, 80, 20, 0.6),
  () => particle(50, 75, 20, 0.6),
];

const createTarget = (pos, direction, withColor) => {
  let color = "black";
  if (withColor) {
    color = rndi(0, 7) === 6 ? "yellow" : "black";
  }
  const target = {
    pos,
    width: 10,
    direction,
    color,
    ttl: rndi(2, 5),
    speed: BASE_SPEED + rnd(0, difficulty),
    update: updateTarget,

  }
  targets.push(target);
}

const updateTarget = function() {
  if (this.pos.x+this.width < 0) {
    if (this.ttl > 0) {
      this.ttl--;
    } else {
      this.color = "black";
    }
    this.pos = vec(100, this.pos.y);
  }

  if (this.pos.x > 100) {
    if (this.ttl > 0) {
      this.ttl--;
    } else {
      this.color = "black";
    }
    this.pos = vec(0-this.width, this.pos.y);
  }

  if (this.direction === "left") {
    this.pos.sub(abs(this.speed), 0);
  } else {
    this.pos.add(abs(this.speed), 0);
  }
}

const createBullet = (pos) => {
  bullet = {
    pos,
    update: updateBullet,
  }
}

const updateBullet = function() {
  this.pos.sub(0, 1.5-SLOWMO);
  if (this.pos.y < - 0) {
    color("red");
    particle(this.pos.x + 2, this.pos.y - 5, 1000, 1);
    color("black");
    lifes--;
    if (lifes < 1) {
      end();
    }
    play("hit");
    bullet = null;
  }
}

const spawnNewTargets = (withColor) => {
  createTarget(vec(100, 45), "left", withColor);
  createTarget(vec(-10, 30), "right", withColor);
  createTarget(vec(100, 15), "left", withColor);
}

function update() {
  if (!ticks) {
    lifes = 3;
    targets = [];
    spawnNewTargets(false);
  }

  if (input.isPressed) {
    SLOWMO = 0.8;
  } else if (input.isJustReleased){
    if (!bullet) {
      play("laser");
      createBullet(vec(48, 75));
    }
    SLOWMO = 0;
  }

  if (bullet) {
    color("light_red");
    rect(bullet.pos, 4, 8);
    color("black");
    bullet.update();
  }

  targets.forEach(t => {
    t.update();
  })

  remove(targets, t => {
    color(t.color);
    if (rect(t.pos, t.width).isColliding.rect.light_red) {
      let points = 1;
      if (t.color === "yellow") {
        if (lifes < 3) {
          play("coin");
          lifes++;
        }
        points = 5;
      }

      addScore(points, t.pos);
      play("explosion");
      particle(t.pos.x, t.pos.y+5, 100);
      bullet = null;
      return true;
    } else {
      return false;
    }
  })

  if (targets.length < 1) {
    spawnNewTargets(true);
  }

  for (let i=0; i < lifes; i++) {
    color("light_purple");
    lifeLines[i]();
    // If we are in slowmo-mo-mo-mode, we draw "charging" particles.
    if (SLOWMO && !bullet) {
      color("light_red");
      muzzleFlashes[lifes-1]();
    }
  }
  color("black");
}
