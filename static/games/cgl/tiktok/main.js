title = "TIKTOK";

description = `
JUMP!
`;

characters = [
  `
llllll
ll l l
ll l l
llllll
 l  l

  `,
  `
llllll
ll l l
ll l l
llllll
 l  l
l  l
  `,
];

/** @type {{animation: string, jumping: boolean, pos: Vector, cooldown: boolean}} */
let p;

options = {
  isPlayingBgm: true,
  seed: 6,
};
/** @type {Vector} */
let origin;
/** @type {Vector} */
let hour_hand;
/** @type {Vector} */
let minute_hand;
let minute_ticks;
let prev_minute_ticks;
let hour_ticks;
let hour_can_tick;
let speed;

const collide = (p, hand) => {
  let a = origin.distanceTo(hand)
  let b = origin.distanceTo(p.pos)
  let c = hand.distanceTo(p.pos)
  let s = (a + b + c) / 2
  let distance = 2 * sqrt(s * (s - a) + (s - b) + (s - c)) / a

  return distance < 0.45
}

function getPosition(tick, stretch) {
  tick -= 15
  tick = tick % 60
  tick = 60 - tick

  let x = cos(2 * PI * (tick / 60.0))
  let y = -1 * sin(2 * PI * (tick / 60.0))

  x *= stretch
  y *= stretch
  x += 50
  y += 50

  return [x, y]
}

function update() {
  if (!ticks) {
    p = {
      animation: "a",
      jumping: false,
      pos: vec(50, 70),
      cooldown: false,
    };

    origin = vec(50, 50);
    hour_hand = vec(50, 32);
    minute_hand = vec(50, 32);

    minute_ticks = 1;
    prev_minute_ticks = 0;
    hour_ticks = 0;
    hour_can_tick = true;
    speed = 0.15;
  }

  if (!p.jumping && input.isJustPressed) {
    p.pos.sub(0, 5)
    p.jumping = true;
    p.animation = "b";
    play("jump");
    setTimeout(() => {
      p.jumping = false,
      p.animation = "a",
      p.pos.add(0, 5)
    }, 600)
  }

  if (collide(p, minute_hand)) {
    if (!p.jumping) {
      play("hit");
      end();
    }

    if (p.jumping && !p.cooldown) {
      play("coin");
      addScore(10+speed*4, vec(p.pos.x + 12, p.pos.y));
      speed += 0.05
      speed = clamp(speed, 0.1, 1.25)

      p.cooldown = true;
      setTimeout(() => { p.cooldown = false }, 300);
    }
  }

  prev_minute_ticks = minute_ticks;
  minute_ticks = (minute_ticks + 1 * speed) % 60;
  if (floor(minute_ticks) !== floor(prev_minute_ticks)) {
    addScore(1)
  }

  if (floor(minute_ticks) === 0) {
    if (hour_can_tick) {
      hour_can_tick = false;
      hour_ticks =  hour_ticks + 5;
    }
  } else if (floor(minute_ticks !== 0)){
    hour_can_tick = true;
  }


  let [mx, my] = getPosition(minute_ticks, 26)
  minute_hand.set({ x: mx, y: my })
  let [hx, hy] = getPosition(hour_ticks, 14)
  hour_hand.set({ x: hx, y: hy })

  // Draw a shadow.
  if (p.jumping) {
    color("black")
    rect(48, 70, 4, 4)
  }

  color("black")
  arc(50, 50, 40, 5, 0, -3.1)
  arc(50, 50, 40, 5, 3.1, 0)
  color("black")
  line(origin, hour_hand, 5)
  color("red")
  line(origin, minute_hand, 5)

  color("yellow")
  char(p.animation, p.pos)
}
